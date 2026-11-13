"""Reglas de movimiento."""

from __future__ import annotations

import ipaddress
import re

from .base import (Config, Event, Hit, Iterator, UNKNOWN, _LOCAL_IPS, _REMOTE_PIPES, _REMOTE_SHELL_CHILDREN, _REMOTE_SHELL_PARENTS, _bursts, _duration, _exe, _is_system_account, _logon_types, _processes, _truncate, _user, defaultdict, rule)
from .base import _is_sysmon, _windows_path

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


def _pipe_label(pipe: str, image: str, created: bool) -> tuple[str, str]:
    """Clasifica nombres conocidos, retirando solo el prefijo de transporte inicial."""
    name = re.sub(r"^(?:\\\\\.\\pipe\\|\\device\\namedpipe\\|\\pipe\\|\\)", "", pipe.lower())
    if re.match(r"^(?:psexesvc|paexec|csexec|remcom)(?:$|[_\-\\]|\d|svc)", name):
        return "canal de una herramienta de administración remota", "low"
    if re.fullmatch(r"(?:msagent|postex)_[a-z0-9_\-]+|status_[0-9a-f]{2,16}|msse-[0-9a-z]+-server", name):
        return "nombre por defecto de un canal de Cobalt Strike", "high"
    if "\\pipe\\" in name:
        return "pipe anidada compatible con suplantación de tokens", "high"
    if re.match(r"^(?:kekeo|tsssp)(?:$|[_\-\\])", name):
        return "canal compatible con herramientas de delegación de credenciales", "medium"
    if created and name == "spoolss" and image and not (_exe(image) == "spoolsv.exe" and _windows_path(image)):
        return "canal spoolss creado por un proceso ajeno al spooler", "high"
    return "", ""


_PIPE_ECHO = re.compile(r'/[ck]\s+echo\s+[^>\r\n]+>\s*"?\\\\\.\\pipe\\[^\s"]+', re.I)


@rule("WLH-028", "Named pipes de herramientas ofensivas", "high", ["T1021.002", "T1559", "T1134"],
      "Sysmon 17/18 y creación de pipes con cmd: canales conocidos de ejecución remota y suplantación.")
def offensive_pipes(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[tuple[str, str, str, str], list[Event]] = defaultdict(list)
    labels: dict[tuple[str, str, str, str], tuple[str, str]] = {}
    for e in events:
        if e.event_id not in (17, 18) or not _is_sysmon(e):
            continue
        pipe, image = e.get("PipeName"), e.get("Image")
        reason, severity = _pipe_label(pipe, image, e.event_id == 17)
        if reason:
            key = (e.computer.lower(), pipe.lower(), image.lower(), reason)
            groups[key].append(e)
            labels[key] = reason, severity
    for key, evs in groups.items():
        reason, severity = labels[key]
        for burst in _bursts(evs, cfg.window, 1):
            yield Hit(burst, f"{reason.capitalize()} en {burst[0].computer or UNKNOWN}",
                      {"pipe": burst[0].get("PipeName"), "proceso": burst[0].get("Image"), "indicador": reason},
                      severity=severity)
    for e in events:
        if e.event_id == 1 and _is_sysmon(e):
            image, command, severity = e.get("Image"), e.get("CommandLine"), "medium"
            if _exe(image) != "cmd.exe":
                continue
        elif e.event_id == 7045 and (e.channel.lower() in ("system", "") or "service control manager" in e.provider.lower()):
            image, command, severity = "", e.get("ImagePath"), "high"
            if not re.match(r'^"?(?:[a-z]:\\windows\\(?:system32|syswow64)\\)?cmd(?:\.exe)?"?\s+', command, re.I):
                continue
        else:
            continue
        if _PIPE_ECHO.search(command):
            yield Hit([e], f"Comando echo hacia una named pipe en {e.computer or UNKNOWN}",
                      {"proceso": image, "línea_de_comandos": _truncate(command), "servicio": e.get("ServiceName")},
                      severity=severity, mitre=["T1134.001"])


_NETWORK_TOOLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
                  "wscript.exe", "cscript.exe", "msbuild.exe", "certutil.exe", "bitsadmin.exe", "notepad.exe"}
_ROUTINE_NETWORK_TOOLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "msbuild.exe", "certutil.exe", "bitsadmin.exe", "notepad.exe"}
_RDP_CLIENTS = {"mstsc.exe", "svchost.exe", "msrdc.exe", "rdcman.exe", "mremoteng.exe", "remotedesktop.exe", "windowsapp.exe"}
_SSH_CLIENTS = {"ssh.exe", "plink.exe", "putty.exe"}


@rule("WLH-031", "Conexiones de red de shells y LOLBins", "medium", ["T1059", "T1105", "T1572"],
      "Sysmon 3: conexiones salientes públicas de intérpretes y LOLBins; acceso RDP por procesos inesperados, también 5156 local.")
def shell_network(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[tuple[str, str, str, str, str, str], list[Event]] = defaultdict(list)
    for e in events:
        is_sysmon = e.event_id == 3 and _is_sysmon(e)
        is_wfp = e.event_id == 5156 and (e.channel.lower() in ("security", "") or "security-auditing" in e.provider.lower())
        if not (is_sysmon or is_wfp):
            continue
        if is_sysmon and e.get("Initiated").lower() == "false":
            continue
        if is_wfp and e.get("Direction").lower() in {"inbound", "entrada", "%%14592"}:
            continue
        image = e.get("Image") if is_sysmon else e.get("Application")
        name = _exe(image)
        if not image or name in {"system", "[system process]"}:
            continue
        address, port = e.get("DestinationIp", "DestAddress"), e.get("DestinationPort", "DestPort")
        try:
            ip = ipaddress.ip_address(address)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
        except ValueError:
            continue
        reason, severity = "", "medium"
        if port == "3389" and not ip.is_unspecified and name not in _RDP_CLIENTS and (is_sysmon or ip.is_loopback):
            reason = "acceso RDP desde un proceso que no es un cliente habitual"
            severity = "low" if name in _SSH_CLIENTS else "high"
        elif is_sysmon and name in _NETWORK_TOOLS and ip.is_global and not ip.is_multicast:
            reason = "conexión pública saliente de un intérprete o LOLBin"
            # PowerShellGet, NuGet, certificados y Notepad moderno tienen tráfico habitual.
            severity = "low" if name in _ROUTINE_NETWORK_TOOLS else "medium"
        if reason:
            groups[(e.computer.lower(), image.lower(), str(ip), port, reason, severity)].append(e)
    for (_, _, address, port, reason, severity), evs in groups.items():
        for burst in _bursts(evs, cfg.window, 1):
            yield Hit(burst, f"{reason.capitalize()} en {burst[0].computer or UNKNOWN}",
                      {"proceso": burst[0].get("Image", "Application"), "destino": address, "puerto": port,
                       "indicador": reason, "conexiones": len(burst)}, severity=severity,
                      mitre=["T1572"] if port == "3389" else ["T1059", "T1105"])


