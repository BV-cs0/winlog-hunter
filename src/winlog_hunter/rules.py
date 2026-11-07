"""Reglas de detección mapeadas a MITRE ATT&CK.

Cada regla recibe la lista de eventos ordenada por fecha y devuelve ``Hit``s.
``run_rules`` los convierte en ``Finding``s con los metadatos de la regla.
Para añadir una regla basta con decorar una función con ``@rule(...)``.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta
from pathlib import PureWindowsPath
from typing import Any, Callable, Iterable, Iterator

from .models import Event, Finding


@dataclass
class Config:
    window: timedelta = timedelta(minutes=5)
    brute_force_threshold: int = 5
    spray_min_accounts: int = 5
    success_lookback: timedelta = timedelta(minutes=30)
    lateral_window: timedelta = timedelta(minutes=30)
    lateral_min_hosts: int = 3


@dataclass
class Hit:
    events: list[Event]
    summary: str
    evidence: dict[str, Any]
    severity: str | None = None
    mitre: list[str] | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    mitre: tuple[str, ...]
    description: str
    func: Callable[[list[Event], Config], Iterable[Hit]]


RULES: list[Rule] = []


def rule(id: str, title: str, severity: str, mitre: list[str], description: str):
    def decorator(func):
        RULES.append(Rule(id, title, severity, tuple(mitre), description, func))
        return func

    return decorator


def run_rules(
    events: Iterable[Event], config: Config | None = None, only: set[str] | None = None
) -> list[Finding]:
    config = config or Config()
    ordered = sorted(events, key=lambda e: e.timestamp)
    findings: list[Finding] = []
    for r in RULES:
        if only and r.id not in only:
            continue
        for hit in r.func(ordered, config):
            evs = hit.events
            findings.append(
                Finding(
                    rule_id=r.id,
                    title=r.title,
                    severity=hit.severity or r.severity,
                    mitre=list(hit.mitre or r.mitre),
                    summary=hit.summary,
                    first_seen=evs[0].timestamp,
                    last_seen=evs[-1].timestamp,
                    computers=sorted({e.computer for e in evs if e.computer}),
                    evidence={k: v for k, v in hit.evidence.items() if v not in ("", None, [], {})},
                    event_count=len(evs),
                )
            )
    findings.sort(key=lambda f: (-f.rank, f.first_seen, f.rule_id))
    return findings


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #

UNKNOWN = "desconocido"
_LOCAL_IPS = {"", "127.0.0.1", "::1"}
_SYSTEM_ACCOUNTS = {"anonymous logon", "system", "local service", "network service"}

LOGON_TYPES = {
    "2": "interactivo",
    "3": "red",
    "4": "batch",
    "5": "servicio",
    "7": "desbloqueo",
    "8": "red, texto claro",
    "9": "nuevas credenciales",
    "10": "RDP",
    "11": "cacheado",
}

FAILURE_REASONS = {
    "0xc000006a": "contraseña incorrecta",
    "0xc0000064": "usuario inexistente",
    "0xc0000234": "cuenta bloqueada",
    "0xc0000072": "cuenta deshabilitada",
    "0xc000006f": "fuera del horario permitido",
    "0xc0000070": "equipo no permitido",
    "0xc0000071": "contraseña caducada",
    "0xc0000193": "cuenta caducada",
    "0xc0000133": "desfase de reloj",
    "0xc000015b": "tipo de logon no concedido",
}


def _user(e: Event) -> str:
    return e.get("TargetUserName")


def _source(e: Event) -> str:
    return e.get("IpAddress", "WorkstationName") or UNKNOWN


def _is_system_account(user: str) -> bool:
    return user.endswith("$") or user.lower() in _SYSTEM_ACCOUNTS or user.upper().startswith(("DWM-", "UMFD-"))


def _logon_label(code: str) -> str:
    return f"{code} ({LOGON_TYPES[code]})" if code in LOGON_TYPES else (code or UNKNOWN)


def _logon_types(events: list[Event]) -> list[str]:
    return sorted({_logon_label(e.get("LogonType")) for e in events})


def _failure_reasons(events: list[Event]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for e in events:
        code = (e.get("SubStatus") or e.get("Status")).lower()
        if code in ("", "0x0"):
            code = e.get("Status").lower()
        counter[FAILURE_REASONS.get(code, code or UNKNOWN)] += 1
    return dict(counter.most_common())


def _duration(events: list[Event]) -> str:
    seconds = int((events[-1].timestamp - events[0].timestamp).total_seconds())
    if seconds < 60:
        return f"{seconds} s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {seconds} s" if seconds else f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min"


def _truncate(text: str, limit: int = 600) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _bursts(
    events: list[Event],
    window: timedelta,
    threshold: int,
    distinct: Callable[[Event], str] | None = None,
) -> list[list[Event]]:
    """Agrupa ráfagas: ``threshold`` eventos (o valores distintos) dentro de ``window``.

    Una vez alcanzado el umbral, la ráfaga se alarga mientras los eventos sigan
    llegando con huecos menores que ``window``, para no duplicar alertas.
    """
    bursts: list[list[Event]] = []
    n = len(events)
    i = j = 0
    while j < n:
        while events[j].timestamp - events[i].timestamp > window:
            i += 1
        current = events[i : j + 1]
        size = len({distinct(e) for e in current}) if distinct else len(current)
        if size >= threshold:
            end = j
            while end + 1 < n and events[end + 1].timestamp - events[end].timestamp <= window:
                end += 1
            bursts.append(events[i : end + 1])
            i = j = end + 1
            continue
        j += 1
    return bursts


_SUSPICIOUS_COMMAND = re.compile(
    r"powershell|pwsh|\bcmd(?:\.exe)?\s+/[ck]\b|mshta|rundll32|regsvr32|wscript|cscript|"
    r"certutil|bitsadmin|%temp%|\\temp\\|\\appdata\\|\\users\\public\\|\\perflogs\\|"
    r"\s-enc\b|-encodedcommand|frombase64string|https?://|\\\\[^\\\s]+\\(?:admin|c|ipc)\$",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Autenticación
# --------------------------------------------------------------------------- #


AccountKey = tuple[str, str, str, str]


def _account_key(e: Event) -> AccountKey:
    """Identidad de la cuenta atacada: usuario + dominio + equipo destino + origen.

    El dominio y el equipo evitan mezclar cuentas locales homónimas (p. ej. el
    'Administrador' local de dos servidores) cuando se analizan logs de varias máquinas.
    """
    domain = e.get("TargetDomainName").split(".", 1)[0].lower()
    return (_user(e).lower(), domain, e.computer.lower(), _source(e))


def _failed_logons(events: list[Event]) -> dict[AccountKey, list[Event]]:
    groups: dict[AccountKey, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id == 4625 and _user(e):
            groups[_account_key(e)].append(e)
    return groups


@rule(
    "WLH-001",
    "Fuerza bruta de credenciales",
    "high",
    ["T1110.001"],
    "Muchos inicios de sesión fallidos (4625) contra la misma cuenta y desde el mismo origen en poco tiempo.",
)
def brute_force(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for (_, _, _, source), evs in _failed_logons(events).items():
        for burst in _bursts(evs, cfg.window, cfg.brute_force_threshold):
            user = _user(burst[0])
            yield Hit(
                burst,
                f"{len(burst)} inicios de sesión fallidos para '{user}' desde {source} en {_duration(burst)}",
                {
                    "usuario": user,
                    "origen": source,
                    "intentos": len(burst),
                    "tipos_de_logon": _logon_types(burst),
                    "motivos": _failure_reasons(burst),
                },
            )


@rule(
    "WLH-002",
    "Password spraying",
    "high",
    ["T1110.003"],
    "Un mismo origen falla el inicio de sesión contra muchas cuentas distintas en poco tiempo.",
)
def password_spray(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id == 4625 and _user(e) and _source(e) != UNKNOWN:
            groups[_source(e)].append(e)
    for source, evs in groups.items():
        for burst in _bursts(evs, cfg.window, cfg.spray_min_accounts, distinct=lambda e: _user(e).lower()):
            accounts = sorted({_user(e).lower(): _user(e) for e in burst}.values(), key=str.lower)
            yield Hit(
                burst,
                f"{source} probó {len(accounts)} cuentas distintas en {_duration(burst)}",
                {
                    "origen": source,
                    "cuentas_distintas": len(accounts),
                    "cuentas": accounts[:25],
                    "intentos": len(burst),
                    "motivos": _failure_reasons(burst),
                },
            )


@rule(
    "WLH-003",
    "Inicio de sesión correcto tras fuerza bruta",
    "critical",
    ["T1110", "T1078"],
    "Un 4624 llega justo después de una ráfaga de 4625 para la misma cuenta y origen: probable credencial comprometida.",
)
def success_after_failures(events: list[Event], cfg: Config) -> Iterator[Hit]:
    failures = _failed_logons(events)
    times = {key: [e.timestamp for e in evs] for key, evs in failures.items()}
    last_alert: dict[AccountKey, Any] = {}
    for e in events:
        if e.event_id != 4624 or not _user(e):
            continue
        key = _account_key(e)
        if key not in failures:
            continue
        lo = bisect_left(times[key], e.timestamp - cfg.success_lookback)
        hi = bisect_right(times[key], e.timestamp)
        prior = failures[key][lo:hi]
        if len(prior) < cfg.brute_force_threshold:
            continue
        if key in last_alert and e.timestamp - last_alert[key] <= cfg.success_lookback:
            continue
        last_alert[key] = e.timestamp
        yield Hit(
            prior + [e],
            f"'{_user(e)}' inició sesión con éxito desde {key[3]} tras {len(prior)} intentos fallidos",
            {
                "usuario": _user(e),
                "dominio": e.get("TargetDomainName"),
                "origen": key[3],
                "intentos_fallidos_previos": len(prior),
                "tipo_de_logon": _logon_label(e.get("LogonType")),
                "id_de_logon": e.get("TargetLogonId"),
            },
        )


@rule(
    "WLH-004",
    "Posible movimiento lateral",
    "high",
    ["T1021"],
    "La misma cuenta inicia sesión por red o RDP (tipos 3/10) en varios equipos desde un mismo origen en poco tiempo.",
)
def lateral_movement(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id != 4624 or e.get("LogonType") not in ("3", "10") or not e.computer:
            continue
        user, ip = _user(e), e.get("IpAddress")
        if not user or _is_system_account(user) or ip in _LOCAL_IPS:
            continue
        groups[(user.lower(), ip)].append(e)
    for (_, ip), evs in groups.items():
        for burst in _bursts(evs, cfg.lateral_window, cfg.lateral_min_hosts, distinct=lambda e: e.computer.lower()):
            hosts = sorted({e.computer for e in burst}, key=str.lower)
            yield Hit(
                burst,
                f"'{_user(burst[0])}' inició sesión en {len(hosts)} equipos desde {ip} en {_duration(burst)}",
                {
                    "usuario": _user(burst[0]),
                    "origen": ip,
                    "equipos_destino": hosts,
                    "tipos_de_logon": _logon_types(burst),
                },
                mitre=["T1021.001"] if all(e.get("LogonType") == "10" for e in burst) else None,
            )


# --------------------------------------------------------------------------- #
# Persistencia, privilegios y evasión
# --------------------------------------------------------------------------- #


@rule(
    "WLH-005",
    "Registro de eventos borrado",
    "critical",
    ["T1070.001"],
    "Se vació el registro de seguridad (1102) u otro registro (104): típico para borrar huellas.",
)
def log_cleared(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        channel, provider = e.channel.lower(), e.provider.lower()
        is_security = e.event_id == 1102 and (channel in ("security", "") or "eventlog" in provider)
        is_other = e.event_id == 104 and (channel == "system" or "eventlog" in provider)
        if not (is_security or is_other):
            continue
        log = "Security" if is_security else (e.get("Channel") or UNKNOWN)
        who = e.get("SubjectUserName")
        yield Hit(
            [e],
            f"Se borró el registro '{log}' en {e.computer or UNKNOWN}" + (f" (usuario: {who})" if who else ""),
            {"registro": log, "usuario": who, "dominio": e.get("SubjectDomainName")},
        )


_REMOTE_EXEC_SERVICE = re.compile(r"^(?:psexesvc|paexec|remcomsvc|csexecsvc)", re.IGNORECASE)


@rule(
    "WLH-006",
    "Nuevo servicio instalado",
    "high",
    ["T1543.003"],
    "Evento 7045. Alta si el servicio ejecuta algo sospechoso o es de ejecución remota (PsExec); baja en otro caso.",
)
def service_installed(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id != 7045:
            continue
        name, image = e.get("ServiceName"), e.get("ImagePath")
        indicators = []
        mitre = ["T1543.003"]
        if _REMOTE_EXEC_SERVICE.match(name):
            indicators.append("servicio típico de ejecución remota (PsExec o similar)")
            mitre += ["T1569.002", "T1021.002"]
        match = _SUSPICIOUS_COMMAND.search(image)
        if match:
            indicators.append(f"comando sospechoso: '{match.group(0).strip()}'")
        yield Hit(
            [e],
            f"Servicio '{name or UNKNOWN}' instalado en {e.computer or UNKNOWN}",
            {
                "servicio": name,
                "ruta": _truncate(image),
                "cuenta": e.get("AccountName"),
                "tipo_de_inicio": e.get("StartType"),
                "indicadores": indicators,
            },
            severity="high" if indicators else "low",
            mitre=mitre,
        )


_TASK_COMMAND = re.compile(r"<Command>(.*?)</Command>", re.IGNORECASE | re.DOTALL)
_TASK_ARGS = re.compile(r"<Arguments>(.*?)</Arguments>", re.IGNORECASE | re.DOTALL)


@rule(
    "WLH-007",
    "Tarea programada creada",
    "high",
    ["T1053.005"],
    "Evento 4698. Alta si la tarea lanza PowerShell, scripts o rutas sospechosas; baja en otro caso.",
)
def scheduled_task(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id != 4698:
            continue
        content = html.unescape(e.get("TaskContent"))
        commands = [c.strip() for c in _TASK_COMMAND.findall(content)]
        arguments = [a.strip() for a in _TASK_ARGS.findall(content)]
        action = " ".join(commands + arguments) or content
        match = _SUSPICIOUS_COMMAND.search(action)
        yield Hit(
            [e],
            f"Tarea '{e.get('TaskName') or UNKNOWN}' creada en {e.computer or UNKNOWN} por {e.get('SubjectUserName') or UNKNOWN}",
            {
                "tarea": e.get("TaskName"),
                "usuario": e.get("SubjectUserName"),
                "accion": _truncate(action),
                "indicadores": [f"comando sospechoso: '{match.group(0).strip()}'"] if match else [],
            },
            severity="high" if match else "low",
        )


@rule(
    "WLH-008",
    "Cuenta de usuario creada",
    "medium",
    ["T1136"],
    "Evento 4720: se creó una cuenta nueva. Revisa si estaba planificada.",
)
def user_created(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id != 4720:
            continue
        target, subject = e.get("TargetUserName", "SamAccountName"), e.get("SubjectUserName")
        yield Hit(
            [e],
            f"Cuenta '{target or UNKNOWN}' creada por '{subject or UNKNOWN}' en {e.computer or UNKNOWN}",
            {"cuenta": target, "creada_por": subject, "dominio": e.get("TargetDomainName")},
        )


_PRIVILEGED_BUILTIN_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-555": "Remote Desktop Users",
}
_PRIVILEGED_DOMAIN_RIDS = {
    "512": "Domain Admins",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
}
_CRITICAL_RIDS = {"512", "518", "519"}
_PRIVILEGED_NAMES = {
    "administrators", "administradores", "domain admins", "admins. del dominio",
    "enterprise admins", "administradores de empresas", "schema admins",
    "administradores de esquema", "backup operators", "operadores de copia de seguridad",
    "account operators", "opers. de cuentas", "server operators", "operadores de servidores",
    "remote desktop users", "usuarios de escritorio remoto", "dnsadmins",
}


def _privileged_group(e: Event) -> tuple[bool, bool]:
    """Devuelve (es_privilegiado, es_critico). Usa SIDs, que no dependen del idioma."""
    sid = e.get("TargetSid").upper()
    if sid in _PRIVILEGED_BUILTIN_SIDS:
        return True, False
    if sid.startswith("S-1-5-21-"):
        rid = sid.rsplit("-", 1)[-1]
        if rid in _PRIVILEGED_DOMAIN_RIDS:
            return True, rid in _CRITICAL_RIDS
    return e.get("TargetUserName").lower() in _PRIVILEGED_NAMES, False


@rule(
    "WLH-009",
    "Miembro añadido a grupo privilegiado",
    "high",
    ["T1098"],
    "Eventos 4728/4732/4756 sobre grupos como Administradores o Admins. del dominio (detectados por SID).",
)
def privileged_group_add(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id not in (4728, 4732, 4756):
            continue
        privileged, critical = _privileged_group(e)
        if not privileged:
            continue
        group = e.get("TargetUserName") or e.get("TargetSid")
        member = e.get("MemberName", "MemberSid")
        yield Hit(
            [e],
            f"'{member or UNKNOWN}' añadido a '{group}' por '{e.get('SubjectUserName') or UNKNOWN}'",
            {
                "grupo": group,
                "sid_grupo": e.get("TargetSid"),
                "miembro": e.get("MemberName"),
                "sid_miembro": e.get("MemberSid"),
                "añadido_por": e.get("SubjectUserName"),
            },
            severity="critical" if critical else None,
        )


# --------------------------------------------------------------------------- #
# Ejecución (Sysmon 1 / Security 4688)
# --------------------------------------------------------------------------- #


@dataclass
class _Process:
    event: Event
    image: str
    command_line: str
    parent: str
    user: str


def _processes(events: list[Event]) -> Iterator[_Process]:
    for e in events:
        if e.event_id == 1 and ("sysmon" in e.channel.lower() or "sysmon" in e.provider.lower() or "Image" in e.data):
            yield _Process(e, e.get("Image"), e.get("CommandLine"), e.get("ParentImage"), e.get("User"))
        elif e.event_id == 4688:
            yield _Process(
                e, e.get("NewProcessName"), e.get("CommandLine"), e.get("ParentProcessName"), e.get("SubjectUserName")
            )


def _exe(path: str) -> str:
    return PureWindowsPath(path).name.lower() if path else ""


_POWERSHELL = {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}
_ENCODED_FLAG = re.compile(r"(?:^|\s)[-/](e[a-z]*)\s+['\"]?([A-Za-z0-9+/=]{16,})", re.IGNORECASE)
_PS_INDICATORS = [
    ("descarga remota", re.compile(
        r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|"
        r"start-bitstransfer|invoke-restmethod|\birm\b", re.IGNORECASE)),
    ("ejecución dinámica (IEX)", re.compile(r"\biex\b|invoke-expression", re.IGNORECASE)),
    ("decodificación base64", re.compile(r"frombase64string", re.IGNORECASE)),
    ("ventana oculta", re.compile(r"(?:^|\s)[-/]w[a-z]*\s+(?:h|hidden|1)\b", re.IGNORECASE)),
    ("sin perfil", re.compile(r"(?:^|\s)[-/]nop(?:rofile)?\b", re.IGNORECASE)),
    ("bypass de política", re.compile(r"(?:^|\s)[-/](?:ep|ex[a-z]*)\s+bypass\b", re.IGNORECASE)),
    ("evasión de AMSI", re.compile(r"amsiutils|amsiinitfailed", re.IGNORECASE)),
]
ENCODED = "comando codificado (-EncodedCommand)"


def decode_powershell(command_line: str) -> str:
    """Decodifica el argumento de -EncodedCommand (base64 de UTF-16LE)."""
    for match in _ENCODED_FLAG.finditer(command_line):
        if not "encodedcommand".startswith(match.group(1).lower()):
            continue
        payload = match.group(2)
        try:
            raw = base64.b64decode(payload + "=" * (-len(payload) % 4))
            return raw.decode("utf-16-le", errors="replace")
        except (binascii.Error, ValueError):
            return ""
    return ""


@rule(
    "WLH-010",
    "PowerShell sospechoso",
    "high",
    ["T1059.001"],
    "PowerShell con comando codificado, descarga + IEX o evasión de AMSI (alta); varias banderas de ocultación (media).",
)
def suspicious_powershell(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        if _exe(p.image) not in _POWERSHELL or not p.command_line:
            continue
        decoded = decode_powershell(p.command_line)
        text = f"{p.command_line}\n{decoded}"
        indicators = [name for name, regex in _PS_INDICATORS if regex.search(text)]
        if decoded:
            indicators.insert(0, ENCODED)
        strong = bool(decoded) or "evasión de AMSI" in indicators or (
            "descarga remota" in indicators and "ejecución dinámica (IEX)" in indicators
        )
        if not strong and len(indicators) < 2:
            continue
        yield Hit(
            [p.event],
            f"PowerShell sospechoso en {p.event.computer or UNKNOWN}: {', '.join(indicators)}",
            {
                "usuario": p.user,
                "proceso_padre": p.parent,
                "linea_de_comandos": _truncate(p.command_line),
                "comando_decodificado": _truncate(decoded),
                "indicadores": indicators,
            },
            severity="high" if strong else "medium",
        )


_LOLBINS = [
    ("certutil.exe", re.compile(r"[-/](?:urlcache|decode|decodehex)\b", re.IGNORECASE), ["T1105", "T1140"],
     "descarga o decodificación de ficheros"),
    ("mshta.exe", re.compile(r"https?://|javascript:|vbscript:", re.IGNORECASE), ["T1218.005"],
     "ejecución de HTA/script remoto"),
    ("rundll32.exe", re.compile(r"javascript:|https?://|\\users\\public\\|\\appdata\\|\\temp\\", re.IGNORECASE),
     ["T1218.011"], "carga de DLL o script desde ubicación sospechosa"),
    ("regsvr32.exe", re.compile(r"/i:\s*https?://|scrobj\.dll", re.IGNORECASE), ["T1218.010"],
     "Squiblydoo (scriptlet remoto)"),
    ("bitsadmin.exe", re.compile(r"/transfer|/addfile|/setnotifycmdline", re.IGNORECASE), ["T1197"],
     "transferencia BITS"),
    ("wmic.exe", re.compile(r"process\s+call\s+create|/node:", re.IGNORECASE), ["T1047"],
     "ejecución vía WMI"),
]


@rule(
    "WLH-011",
    "Uso malicioso de binario del sistema (LOLBin)",
    "high",
    ["T1218"],
    "certutil, mshta, rundll32, regsvr32, bitsadmin o wmic usados con argumentos típicos de ataque.",
)
def lolbins(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        exe = _exe(p.image)
        for name, pattern, mitre, technique in _LOLBINS:
            if exe == name and pattern.search(p.command_line):
                yield Hit(
                    [p.event],
                    f"{name} usado para {technique} en {p.event.computer or UNKNOWN}",
                    {
                        "binario": name,
                        "tecnica": technique,
                        "usuario": p.user,
                        "proceso_padre": p.parent,
                        "linea_de_comandos": _truncate(p.command_line),
                    },
                    mitre=mitre,
                )
                break


_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe", "mspub.exe", "visio.exe"}
_SHELLS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe", "wmic.exe",
}


@rule(
    "WLH-012",
    "Office lanzando una shell",
    "high",
    ["T1566.001", "T1204.002"],
    "Word, Excel, Outlook... abren cmd, PowerShell u otros intérpretes: patrón clásico de documento malicioso.",
)
def office_child_process(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        parent, child = _exe(p.parent), _exe(p.image)
        if parent in _OFFICE and child in _SHELLS:
            yield Hit(
                [p.event],
                f"{parent} lanzó {child} en {p.event.computer or UNKNOWN}",
                {
                    "proceso_padre": p.parent,
                    "proceso_hijo": p.image,
                    "usuario": p.user,
                    "linea_de_comandos": _truncate(p.command_line),
                },
            )
