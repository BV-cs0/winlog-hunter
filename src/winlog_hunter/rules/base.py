"""Reglas de detección mapeadas a MITRE ATT&CK.

Cada regla recibe la lista de eventos ordenada por fecha y devuelve ``Hit``s.
``run_rules`` los convierte en ``Finding``s con los metadatos de la regla.
Para añadir una regla basta con decorar una función con ``@rule(...)``.
"""

from __future__ import annotations

import base64
import binascii
import html
import ntpath
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from heapq import merge
from functools import cached_property, lru_cache
from dataclasses import dataclass
from datetime import timedelta
from pathlib import PureWindowsPath
from typing import Any, Callable, Iterable, Iterator

from ..models import Event, Finding


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
    eventos: frozenset = frozenset()
    filtro: Callable[[Event], bool] | None = None
    agrupar_por: tuple[str, ...] | None = None

    def acepta(self, e: Event) -> bool:
        return (e.event_id in self.eventos or (e.channel.lower(), e.event_id) in self.eventos) and (
            self.filtro is None or self.filtro(e))


RULES: list[Rule] = []


def rule(id: str, title: str, severity: str, mitre: list[str], description: str,
         *, eventos=(), filtro=None, agrupar_por=None):
    def decorator(func):
        seleccion = frozenset((x[0].lower(), x[1]) if isinstance(x, tuple) else x for x in eventos)
        RULES.append(Rule(id, title, severity, tuple(mitre), description, func,
                          seleccion, filtro, tuple(agrupar_por) if agrupar_por is not None else None))
        return func

    return decorator


@dataclass
class Plan:
    """Selección serializable que comparten los loaders y los workers."""
    reglas: tuple[Rule, ...]

    @cached_property
    def ids(self):
        return {x[1] if isinstance(x, tuple) else x for r in self.reglas for x in r.eventos}

    def acepta(self, e: Event) -> bool:
        return any(r.acepta(e) for r in self.por_id.get(e.event_id, ()))

    @cached_property
    def por_id(self):
        indice = defaultdict(list)
        for r in self.reglas:
            for i in {x[1] if isinstance(x, tuple) else x for x in r.eventos}:
                indice[i].append(r)
        return dict(indice)


def planificar(reglas=None) -> Plan:
    """Calcula la unión de los eventos pedidos por las reglas seleccionadas."""
    return Plan(tuple(RULES if reglas is None else reglas))


class _EventosRegla(list):
    """Lista normal con normalización de procesos compartida solo durante este análisis."""
    __slots__ = ("cache_procesos", "clave_procesos")


_CAMPOS_DE_INSTANCIA = frozenset({
    "processid", "newprocessid", "parentprocessid", "processguid", "parentprocessguid",
    "logonid", "logonguid", "subjectlogonid", "targetlogonid", "eventrecordid",
    "recordid", "recordnumber", "utctime", "timestamp", "timecreated", "systemtime",
})


def _congelar(value):
    """Clave estable que conserva todos los valores de las evidencias."""
    if isinstance(value, dict):
        return tuple(sorted((k, _congelar(v)) for k, v in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_congelar(v) for v in value)
    return value


def _contexto_repetidos(events):
    """Compara los campos completos, incluidos sufijos truncados en el informe.

    Omite fechas, PID y GUID de instancia: cambian al repetir la misma acción.
    La evidencia y el resumen se comparan además, para no ocultar diferencias.
    """
    return tuple(sorted({(e.event_id, e.channel, e.provider,
                          tuple(sorted((k, v) for k, v in e.data.items()
                                       if k.lower() not in _CAMPOS_DE_INSTANCIA))) for e in events}))


def run_rules(
    events: Iterable[Event], config: Config | None = None, only: set[str] | None = None
) -> list[Finding]:
    config = config or Config()
    ordered = sorted(events, key=lambda e: e.timestamp)
    indice = defaultdict(list)
    for pos, e in enumerate(ordered):
        indice[e.event_id].append((pos, e))
    findings: list[Finding] = []
    cache_procesos = {}
    selecciones = {}
    for r in RULES:
        if only and r.id not in only:
            continue
        ids = {x[1] if isinstance(x, tuple) else x for x in r.eventos}
        clave_seleccion = (r.eventos, id(r.filtro))
        propios = selecciones.get(clave_seleccion)
        if propios is None:
            seleccion = merge(*(indice[i] for i in ids), key=lambda item: item[0])
            # El índice ya garantiza el event_id: acepta() solo hace falta si la regla
            # restringe por canal o tiene un filtro propio.
            if r.filtro is None and not any(isinstance(x, tuple) for x in r.eventos):
                propios = _EventosRegla(e for _, e in seleccion)
            else:
                propios = _EventosRegla(e for _, e in seleccion if r.acepta(e))
            propios.cache_procesos = cache_procesos
            propios.clave_procesos = (frozenset(x for x in r.eventos if (x[1] if isinstance(x, tuple) else x) in (1, 4688)), id(r.filtro))
            selecciones[clave_seleccion] = propios
        agrupados = {}
        for hit in r.func(propios, config):
            evs = hit.events
            finding = Finding(
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
            if r.agrupar_por is not None:
                clave = (finding.severity, tuple(finding.computers), tuple(finding.mitre),
                         tuple(_congelar(finding.evidence.get(k)) for k in r.agrupar_por),
                         finding.summary, _congelar(finding.evidence), _contexto_repetidos(evs))
                anterior = agrupados.get(clave)
                if anterior is not None:
                    anterior.veces += 1
                    anterior.event_count += finding.event_count
                    anterior.first_seen = min(anterior.first_seen, finding.first_seen)
                    anterior.last_seen = max(anterior.last_seen, finding.last_seen)
                    continue
                agrupados[clave] = finding
            findings.append(finding)
    findings.sort(key=lambda f: (-f.rank, f.first_seen, f.rule_id))
    return findings


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


_REMOTE_EXEC_SERVICE = re.compile(r"^(?:psexesvc|paexec|remcomsvc|csexecsvc)", re.IGNORECASE)


_TASK_COMMAND = re.compile(r"<Command>(.*?)</Command>", re.IGNORECASE | re.DOTALL)


_TASK_ARGS = re.compile(r"<Arguments>(.*?)</Arguments>", re.IGNORECASE | re.DOTALL)


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


@dataclass
class _Process:
    __slots__ = ("event", "image", "command_line", "parent", "user")
    event: Event
    image: str
    command_line: str
    parent: str
    user: str


def _processes(events: list[Event]) -> Iterator[_Process]:
    if isinstance(events, _EventosRegla):
        key = events.clave_procesos
        if key not in events.cache_procesos:
            events.cache_procesos[key] = list(_processes(list(events)))
        yield from events.cache_procesos[key]
        return
    procesos_4688 = {}
    for e in events:
        if e.event_id == 1 and ("sysmon" in e.channel.lower() or "sysmon" in e.provider.lower() or "Image" in e.data):
            yield _Process(e, e.get("Image"), e.get("CommandLine"), e.get("ParentImage"), e.get("User"))
        elif e.event_id == 4688:
            equipo = e.computer.lower()
            imagen = e.get("NewProcessName")
            padre = e.get("ParentProcessName") or procesos_4688.get(
                (equipo, _registry_number(e.get("ProcessId"))), "")
            pid = _registry_number(e.get("NewProcessId"))
            if pid is not None:
                procesos_4688[equipo, pid] = imagen
            yield _Process(
                e, imagen, e.get("CommandLine"), padre, e.get("SubjectUserName")
            )


@lru_cache(maxsize=8192)
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


_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe", "mspub.exe", "visio.exe"}


_SHELLS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe", "wmic.exe",
}


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


def _windows_path(path: str, folders: tuple[str, ...] = ("system32", "syswow64", "winsxs")) -> bool:
    """Comprueba directorios de Windows completos, sin aceptar prefijos parecidos."""
    path = ntpath.normpath(path.strip('"')).lower()
    return bool(re.match(r"^[a-z]:\\windows\\(?:" + "|".join(map(re.escape, folders)) + r")\\", path))


def _program_files_path(path: str) -> bool:
    """Reconoce Program Files por directorio completo, en cualquier unidad."""
    return bool(re.match(r"^[a-z]:\\program files(?: \(x86\))?\\", ntpath.normpath(path).lower()))


def _user_path(path: str) -> bool:
    """Rutas de perfiles y temporales; ProgramData no es escribible por completo."""
    return bool(re.match(r"^[a-z]:\\(?:users\\|temp\\|windows\\temp\\|perflogs\\)",
                         ntpath.normpath(path).lower()))


def _maintenance_process(path: str) -> bool:
    """Instaladores habituales, acotados a sus rutas de instalación."""
    name = _exe(path)
    if _windows_path(path) and name in {"msiexec.exe", "trustedinstaller.exe", "tiworker.exe", "setuphost.exe", "dismhost.exe"}:
        return True
    if _windows_path(path, ("servicing",)) and name == "trustedinstaller.exe":
        return True
    if re.match(r"^[a-z]:\\users\\[^\\]+\\appdata\\local\\microsoft\\(?:"
                r"onedrive\\(?:[^\\]+\\)?onedrive(?:setup)?\.exe|teams\\update\.exe)$",
                ntpath.normpath(path).lower()):
        return True
    return bool(re.match(
        r"^[a-z]:\\program files(?: \(x86\))?\\(?:"
        r"common files\\microsoft shared\\clicktorun\\officeclicktorun\.exe|"
        r"microsoft onedrive\\(?:[^\\]+\\)?onedrivesetup\.exe|"
        r"google\\(?:update|googleupdater)\\.*(?:googleupdate|updater)\.exe)$",
        ntpath.normpath(path).lower()))


def _debugger_process(path: str) -> bool:
    """Depuradores conocidos en sus directorios; no se confía solo en el nombre."""
    name = _exe(path)
    return bool(re.match(r"^[a-z]:\\program files(?: \(x86\))?\\(?:microsoft visual studio\\|windows kits\\|debugging tools for windows[^\\]*\\)",
                         ntpath.normpath(path).lower())) and name in {
        "devenv.exe", "msvsmon.exe", "vsdebugconsole.exe", "vsdebugeng.exe", "windbg.exe", "cdb.exe",
    }


def _browser_root(path: str) -> str:
    """Devuelve el directorio de un navegador habitual, también en instalaciones por usuario."""
    match = re.match(
        r"^([a-z]:\\(?:program files(?: \(x86\))?\\(?:google\\chrome\\application|mozilla firefox|"
        r"microsoft\\(?:edge|edgewebview)\\application)|users\\[^\\]+\\appdata\\local\\(?:"
        r"google\\chrome\\application|microsoft\\(?:edge|edgewebview)\\application))\\)",
        ntpath.normpath(path).lower())
    return match.group(1) if match and _exe(path) in {"chrome.exe", "firefox.exe", "msedge.exe", "msedgewebview2.exe", "crashpad_handler.exe"} else ""


def _registry_number(text: str) -> int | None:
    """Lee DWORD/QWORD de Sysmon y exportaciones de texto sin confundir datos vacíos con cero."""
    match = re.fullmatch(r"(?:(?:dword|qword)\s*\(\s*)?(0x[0-9a-f]+|\d+)\s*\)?", text.strip(), re.I)
    if not match:
        return None
    value = match.group(1)
    return int(value, 16 if value.lower().startswith("0x") else 10)


_DUMP_COMMANDS = [
    ("comsvcs.dll MiniDump", re.compile(r"comsvcs(?:\.dll)?[\s,]+#?(?:minidump|24)\b", re.IGNORECASE), "T1003.001"),
    ("procdump contra LSASS", re.compile(r"procdump.*\blsass", re.IGNORECASE), "T1003.001"),
    ("copia de la base de AD (ntdsutil)", re.compile(r"ntdsutil.*\bifm\b", re.IGNORECASE), "T1003.003"),
    ("copia de ntds.dit", re.compile(r"\\ntds\.dit\b", re.IGNORECASE), "T1003.003"),
    ("copia del registro SAM/SECURITY",
     re.compile(r"\breg(?:\.exe)?\s+save\s+hklm\\(?:sam|security|system)\b", re.IGNORECASE), "T1003.002"),
    ("Mimikatz", re.compile(r"sekurlsa::|lsadump::|kerberos::golden|privilege::debug", re.IGNORECASE), "T1003"),
]


_REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}


_REMOTE_PIPES = {
    "svcctl": ("el gestor de servicios remoto (PsExec, sc \\\\equipo)", ["T1569.002", "T1021.002"]),
    "atsvc": ("el programador de tareas remoto", ["T1053.002", "T1021.002"]),
    "psexesvc": ("el canal de PsExec", ["T1569.002", "T1021.002"]),
    "remcom_communicaton": ("el canal de RemCom", ["T1569.002", "T1021.002"]),
    "paexec": ("el canal de PAExec", ["T1569.002", "T1021.002"]),
}


_REMOTE_SHELL_PARENTS = {
    "wmiprvse.exe": ("WMI", ["T1047"]),
    "wsmprovhost.exe": ("PowerShell Remoting", ["T1021.006"]),
    "winrshost.exe": ("WinRM (winrs)", ["T1021.006"]),
}


_REMOTE_SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe"}


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


