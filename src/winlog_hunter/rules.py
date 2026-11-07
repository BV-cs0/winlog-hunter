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
    ["T1685.005"],
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
                "acción": _truncate(action),
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
                "línea_de_comandos": _truncate(p.command_line),
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
                        "técnica": technique,
                        "usuario": p.user,
                        "proceso_padre": p.parent,
                        "línea_de_comandos": _truncate(p.command_line),
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
                    "línea_de_comandos": _truncate(p.command_line),
                },
            )


# --------------------------------------------------------------------------- #
# Acceso a credenciales
# --------------------------------------------------------------------------- #

_PROCESS_VM_READ = 0x0010
_LSASS_ALLOWED = {
    "msmpeng.exe", "mssense.exe", "csrss.exe", "wininit.exe", "svchost.exe", "lsm.exe", "services.exe",
    "wmiprvse.exe", "taskmgr.exe", "procexp64.exe", "procexp.exe", "vmtoolsd.exe", "searchindexer.exe",
}
_DUMP_TOOLS = re.compile(
    r"mimikatz|procdump|dumpert|outflank|nanodump|pypykatz|sqldumper|rdrleakdiag|comsvcs|dbghelp|dbgcore",
    re.IGNORECASE,
)


def _is_sysmon(e: Event) -> bool:
    return "sysmon" in (e.channel + e.provider).lower()


@rule(
    "WLH-013",
    "Acceso a la memoria de LSASS",
    "critical",
    ["T1003.001"],
    "Sysmon 10: un proceso abre lsass.exe con permiso de lectura de memoria. Así roban contraseñas Mimikatz, procdump o comsvcs.",
)
def lsass_access(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id != 10 or not _is_sysmon(e) or _exe(e.get("TargetImage")) != "lsass.exe":
            continue
        source, mask, trace = e.get("SourceImage"), e.get("GrantedAccess").lower(), e.get("CallTrace")
        try:
            can_read = bool(int(mask, 16) & _PROCESS_VM_READ)
        except ValueError:
            can_read = False
        tool = _DUMP_TOOLS.search(f"{source} {trace}")
        trusted = _exe(source) in _LSASS_ALLOWED and source.lower().startswith(("c:\\windows\\", "c:\\program"))
        if not can_read or (trusted and not tool):
            continue
        indicators = []
        if tool:
            indicators.append(f"herramienta de volcado: '{tool.group(0)}'")
        if "unknown(" in trace.lower():
            indicators.append("código sin módulo en la pila (inyectado o reflectivo)")
        yield Hit(
            [e],
            f"{_exe(source) or UNKNOWN} accedió a la memoria de lsass.exe en {e.computer or UNKNOWN}",
            {
                "proceso_origen": source,
                "permisos": mask,
                "usuario": e.get("SourceUser"),
                "indicadores": indicators,
            },
            severity="critical" if indicators else "high",
        )


_DUMP_COMMANDS = [
    ("comsvcs.dll MiniDump", re.compile(r"comsvcs(?:\.dll)?[\s,]+#?(?:minidump|24)\b", re.IGNORECASE), "T1003.001"),
    ("procdump contra LSASS", re.compile(r"procdump.*\blsass", re.IGNORECASE), "T1003.001"),
    ("copia de la base de AD (ntdsutil)", re.compile(r"ntdsutil.*\bifm\b", re.IGNORECASE), "T1003.003"),
    ("copia de ntds.dit", re.compile(r"\\ntds\.dit\b", re.IGNORECASE), "T1003.003"),
    ("copia del registro SAM/SECURITY",
     re.compile(r"\breg(?:\.exe)?\s+save\s+hklm\\(?:sam|security|system)\b", re.IGNORECASE), "T1003.002"),
    ("Mimikatz", re.compile(r"sekurlsa::|lsadump::|kerberos::golden|privilege::debug", re.IGNORECASE), "T1003"),
]


@rule(
    "WLH-014",
    "Comando de volcado de credenciales",
    "critical",
    ["T1003"],
    "Sysmon 1/4688: comsvcs MiniDump, procdump contra LSASS, ntdsutil IFM, reg save de SAM o comandos de Mimikatz.",
)
def credential_dump_command(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        for name, pattern, mitre in _DUMP_COMMANDS:
            if pattern.search(p.command_line):
                yield Hit(
                    [p.event],
                    f"{name} en {p.event.computer or UNKNOWN}",
                    {
                        "técnica": name,
                        "usuario": p.user,
                        "proceso": p.image,
                        "proceso_padre": p.parent,
                        "línea_de_comandos": _truncate(p.command_line),
                    },
                    mitre=[mitre],
                )
                break


# GUIDs de los derechos de replicación de directorio (DS-Replication-Get-Changes*).
_REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}


@rule(
    "WLH-015",
    "DCSync",
    "critical",
    ["T1003.006"],
    "Evento 4662 con derechos de replicación de AD pedidos por una cuenta que no es un controlador de dominio.",
)
def dcsync(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id != 4662:
            continue
        props = e.get("Properties").lower()
        user = e.get("SubjectUserName")
        if not user or _is_system_account(user) or not any(g in props for g in _REPLICATION_GUIDS):
            continue
        groups[(user.lower(), e.computer.lower())].append(e)
    for evs in groups.values():
        for burst in _bursts(evs, cfg.window, 1):
            props = " ".join(x.get("Properties").lower() for x in burst)
            yield Hit(
                burst,
                f"'{burst[0].get('SubjectUserName')}' pidió replicar el directorio en {burst[0].computer or UNKNOWN}",
                {
                    "usuario": burst[0].get("SubjectUserName"),
                    "dominio": burst[0].get("SubjectDomainName"),
                    "derechos": sorted(n for g, n in _REPLICATION_GUIDS.items() if g in props),
                },
            )


@rule(
    "WLH-016",
    "Kerberoasting",
    "high",
    ["T1558.003"],
    "Eventos 4769 pidiendo tickets de servicio con cifrado RC4 (0x17) para cuentas de usuario: típico de Rubeus o GetUserSPNs.",
)
def kerberoasting(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id != 4769 or e.get("TicketEncryptionType").lower() != "0x17":
            continue
        if e.get("Status").lower() not in ("", "0x0"):
            continue
        service, user = e.get("ServiceName"), e.get("TargetUserName").split("@", 1)[0]
        if not service or service.endswith("$") or service.lower().startswith("krbtgt") or user.endswith("$"):
            continue
        groups[user.lower()].append(e)
    for evs in groups.values():
        for burst in _bursts(evs, cfg.window, 1):
            services = sorted({e.get("ServiceName") for e in burst}, key=str.lower)
            user = burst[0].get("TargetUserName").split("@", 1)[0]
            yield Hit(
                burst,
                f"'{user}' pidió {len(burst)} ticket(s) RC4 para {len(services)} servicio(s)",
                {
                    "usuario": user,
                    "origen": burst[0].get("IpAddress").replace("::ffff:", ""),
                    "servicios": services[:25],
                    "cifrado": "RC4 (0x17)",
                },
                severity="high" if len(services) >= 2 else "medium",
            )


# --------------------------------------------------------------------------- #
# Movimiento lateral y ejecución remota
# --------------------------------------------------------------------------- #

_REMOTE_PIPES = {
    "svcctl": ("el gestor de servicios remoto (PsExec, sc \\\\equipo)", ["T1569.002", "T1021.002"]),
    "atsvc": ("el programador de tareas remoto", ["T1053.002", "T1021.002"]),
    "psexesvc": ("el canal de PsExec", ["T1569.002", "T1021.002"]),
    "remcom_communicaton": ("el canal de RemCom", ["T1569.002", "T1021.002"]),
    "paexec": ("el canal de PAExec", ["T1569.002", "T1021.002"]),
}


@rule(
    "WLH-017",
    "Ejecución remota por SMB",
    "high",
    ["T1021.002"],
    "Evento 5145: acceso remoto a los canales de servicios, tareas o PsExec, o un ejecutable copiado a ADMIN$/C$.",
)
def smb_remote_exec(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id != 5145:
            continue
        share, target = e.get("ShareName").lower(), e.get("RelativeTargetName").lower()
        ip = e.get("IpAddress")
        if ip in _LOCAL_IPS:
            continue
        what = ""
        if share.endswith("ipc$"):
            what = next((pipe for pipe in _REMOTE_PIPES if target.startswith(pipe)), "")
        elif share.endswith(("admin$", "c$")) and target.endswith((".exe", ".dll", ".bat", ".ps1", ".vbs")):
            what = "binario"
        if what:
            groups[(ip, e.computer.lower(), what)].append(e)
    for (ip, _, what), evs in groups.items():
        for burst in _bursts(evs, cfg.window, 1):
            if what == "binario":
                label, mitre = "un ejecutable copiado a un recurso administrativo", ["T1021.002", "T1570"]
                files = sorted({x.get("RelativeTargetName") for x in burst})[:10]
            else:
                (label, mitre), files = _REMOTE_PIPES[what], []
            yield Hit(
                burst,
                f"{ip} usó {label} en {burst[0].computer or UNKNOWN}",
                {
                    "origen": ip,
                    "usuario": burst[0].get("SubjectUserName"),
                    "recurso": burst[0].get("ShareName"),
                    "canal": "" if files else burst[0].get("RelativeTargetName"),
                    "ficheros": files,
                },
                mitre=mitre,
            )


_REMOTE_SHELL_PARENTS = {
    "wmiprvse.exe": ("WMI", ["T1047"]),
    "wsmprovhost.exe": ("PowerShell Remoting", ["T1021.006"]),
    "winrshost.exe": ("WinRM (winrs)", ["T1021.006"]),
}
_REMOTE_SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe"}


@rule(
    "WLH-018",
    "Shell lanzada por un servicio remoto",
    "high",
    ["T1047", "T1021.006"],
    "WMI o WinRM abren cmd o PowerShell: así ejecutan comandos wmiexec, Invoke-Command o winrs.",
)
def remote_service_shell(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        parent, child = _exe(p.parent), _exe(p.image)
        if parent not in _REMOTE_SHELL_PARENTS or child not in _REMOTE_SHELL_CHILDREN:
            continue
        via, mitre = _REMOTE_SHELL_PARENTS[parent]
        yield Hit(
            [p.event],
            f"{child} lanzado vía {via} en {p.event.computer or UNKNOWN}",
            {
                "vía": via,
                "proceso_padre": p.parent,
                "proceso_hijo": p.image,
                "usuario": p.user,
                "línea_de_comandos": _truncate(p.command_line),
            },
            mitre=mitre,
        )


# --------------------------------------------------------------------------- #
# Persistencia (Sysmon 12/13 y 19/20/21)
# --------------------------------------------------------------------------- #

_PERSISTENCE_KEYS = [
    (re.compile(r"\\currentversion\\(?:run|runonce|runonceex|runservices)\\", re.I), "la clave Run", ["T1547.001"]),
    (re.compile(r"\\policies\\explorer\\run\\", re.I), "la clave Run de directivas", ["T1547.001"]),
    (re.compile(r"\\winlogon\\(?:shell|userinit)$", re.I), "Winlogon (Shell/Userinit)", ["T1547.004"]),
    (re.compile(r"\\image file execution options\\[^\\]+\\(?:debugger|globalflag)$", re.I),
     "Image File Execution Options", ["T1546.012"]),
    (re.compile(r"\\silentprocessexit\\[^\\]+\\monitorprocess$", re.I), "SilentProcessExit", ["T1546.012"]),
    (re.compile(r"\\windows\\appinit_dlls$", re.I), "AppInit_DLLs", ["T1546.010"]),
    (re.compile(r"\\(?:user )?shell folders\\(?:common )?startup$", re.I), "la carpeta de Inicio", ["T1547.001"]),
    (re.compile(r"\\session manager\\(?:bootexecute|setupexecute)$", re.I), "BootExecute", ["T1547.001"]),
    (re.compile(r"^hku\\[^\\]+(?:\\software\\classes|_classes)\\clsid\\[^\\]+\\(?:inprocserver32|localserver32|treatas)\\",
                re.I), "un objeto COM del usuario", ["T1546.015"]),
    (re.compile(r"\\sam\\sam\\domains\\account\\users\\names\\[^\\]+\$(?:\\|$)", re.I),
     "una cuenta local oculta (nombre acabado en $)", ["T1564.002"]),
    (re.compile(r"\\sam\\sam\\domains\\account\\users\\[0-9a-f]{8}\\f$", re.I),
     "el RID de una cuenta (RID hijacking)", ["T1098"]),
    (re.compile(r"\\lsa\\(?:security packages|authentication packages|notification packages)$", re.I),
     "los paquetes de seguridad de LSA", ["T1547.005"]),
    (re.compile(r"\\microsoft\\netsh\\", re.I), "las DLL auxiliares de netsh", ["T1546.007"]),
]
_INSTALLERS = re.compile(
    r"^c:\\(?:windows\\(?:system32|syswow64)\\(?:msiexec|services|trustedinstaller)\.exe|"
    r"windows\\servicing\\|windows\\winsxs\\.*tiworker\.exe|"
    r"program files(?: \(x86\))?\\(?:windows defender|microsoft onedrive|google\\update))",
    re.IGNORECASE,
)


@rule(
    "WLH-019",
    "Persistencia en el registro",
    "high",
    ["T1547.001"],
    "Sysmon 13: se escribe en claves de arranque (Run, Winlogon, IFEO, AppInit, LSA, COM...) desde un proceso que no es un instalador.",
)
def registry_persistence(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id not in (12, 13, 14) or not _is_sysmon(e):
            continue
        key, image = e.get("TargetObject", "NewName"), e.get("Image")
        if not key or _INSTALLERS.match(image):
            continue
        for pattern, label, mitre in _PERSISTENCE_KEYS:
            if not pattern.search(key):
                continue
            if "RID" in label and _exe(image) == "lsass.exe":
                break  # LSASS actualiza ese valor en cada inicio de sesión
            details = e.get("Details")
            suspicious = _SUSPICIOUS_COMMAND.search(details) or _SUSPICIOUS_COMMAND.search(image)
            yield Hit(
                [e],
                f"{_exe(image) or UNKNOWN} modificó {label} en {e.computer or UNKNOWN}",
                {
                    "clave": key,
                    "valor": _truncate(details),
                    "proceso": image,
                    "usuario": e.get("User"),
                },
                mitre=mitre,
                severity="medium" if "Run" in label and not suspicious else None,
            )
            break


@rule(
    "WLH-020",
    "Persistencia con WMI",
    "high",
    ["T1546.003"],
    "Sysmon 19/20/21: se crea un filtro, consumidor o enlace de eventos WMI que ejecuta algo de forma permanente.",
)
def wmi_persistence(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id in (19, 20, 21) and _is_sysmon(e) and e.get("Operation").lower() in ("", "created", "modified"):
            groups[e.computer.lower()].append(e)
    for evs in groups.values():
        for burst in _bursts(evs, cfg.window, 1):
            consumer = next((x for x in burst if x.event_id == 20), None)
            filt = next((x for x in burst if x.event_id == 19), None)
            name = (consumer or filt or burst[0]).get("Name", "Consumer").strip('"')
            yield Hit(
                burst,
                f"Suscripción WMI '{name or UNKNOWN}' creada en {burst[0].computer or UNKNOWN}",
                {
                    "nombre": name,
                    "usuario": burst[0].get("User"),
                    "consulta": _truncate(filt.get("Query").strip('"')) if filt else "",
                    "acción": _truncate(consumer.get("Destination").strip('"')) if consumer else "",
                    "tipo": consumer.get("Type") if consumer else "",
                },
            )


# --------------------------------------------------------------------------- #
# PowerShell Script Block Logging (4104)
# --------------------------------------------------------------------------- #

_SCRIPT_BLOCK_INDICATORS = [
    ("volcado de LSASS", re.compile(r"minidumpwritedump|out-minidump", re.I), "T1003.001"),
    ("Mimikatz", re.compile(r"invoke-mimikatz|sekurlsa::|lsadump::", re.I), "T1003"),
    ("evasión de AMSI", re.compile(r"amsiutils|amsiinitfailed|amsiscanbuffer", re.I), "T1685"),
    ("ventana falsa de credenciales", re.compile(r"promptforcredential", re.I), "T1056.002"),
    ("Kerberoasting", re.compile(r"invoke-kerberoast|kerberosrequestorsecuritytoken", re.I), "T1558.003"),
    ("código comprimido cargado en memoria", re.compile(
        r"(?:gzipstream|deflatestream)[\s\S]{0,300}frombase64string|frombase64string[\s\S]{0,300}(?:gzipstream|deflatestream)",
        re.I), "T1027"),
    ("inyección de código", re.compile(r"virtualalloc[\s\S]{0,500}createthread|createremotethread|writeprocessmemory", re.I),
     "T1055"),
    ("PowerSploit / Empire", re.compile(r"invoke-shellcode|invoke-reflectivepeinjection|invoke-empire", re.I), "T1059.001"),
]


@rule(
    "WLH-021",
    "Script de PowerShell malicioso",
    "high",
    ["T1059.001"],
    "Evento 4104 (Script Block Logging): el código ejecutado contiene volcado de LSASS, Mimikatz, evasión de AMSI, inyección...",
)
def malicious_script_block(events: list[Event], cfg: Config) -> Iterator[Hit]:
    seen: set[str] = set()
    for e in events:
        text = e.get("ScriptBlockText") if e.event_id == 4104 else ""
        found = [(name, mitre) for name, regex, mitre in _SCRIPT_BLOCK_INDICATORS if text and regex.search(text)]
        block = e.get("ScriptBlockId") or text[:200]
        if not found or block in seen:
            continue
        seen.add(block)
        yield Hit(
            [e],
            f"Script de PowerShell con {', '.join(n for n, _ in found)} en {e.computer or UNKNOWN}",
            {
                "indicadores": [n for n, _ in found],
                "ruta": e.get("Path"),
                "fragmento": _truncate(text, 400),
            },
            mitre=sorted({"T1059.001", *(m for _, m in found)}),
            severity="critical" if any(m.startswith("T1003") for _, m in found) else None,
        )
