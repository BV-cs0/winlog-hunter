"""Reglas de movimiento."""

from __future__ import annotations

from .base import (Config, Event, Hit, Iterator, UNKNOWN, _LOCAL_IPS, _REMOTE_PIPES, _REMOTE_SHELL_CHILDREN, _REMOTE_SHELL_PARENTS, _bursts, _duration, _exe, _is_system_account, _logon_types, _processes, _truncate, _user, defaultdict, rule)

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


