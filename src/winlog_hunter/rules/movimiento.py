"""Reglas de movimiento."""

from __future__ import annotations

import ipaddress
import ntpath
import re
from datetime import timedelta

from .base import _ipc, _pipe_smb

from .base import (Config, Event, Hit, Iterator, UNKNOWN, _LOCAL_IPS, _REMOTE_PIPES, _REMOTE_SHELL_CHILDREN, _REMOTE_SHELL_PARENTS, _bursts, _duration, _exe, _is_system_account, _logon_types, _processes, _truncate, _user, defaultdict, rule)
from .base import _is_sysmon, _program_files_path, _registry_number, _user_path, _windows_path

@rule(
    "WLH-004",
    "Posible movimiento lateral",
    "high",
    ["T1021"],
    "La misma cuenta inicia sesión por red o RDP (tipos 3/10) en varios equipos desde un mismo origen en poco tiempo.",
    eventos={4624},
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
    eventos={5145},
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
    "WMI o WinRM abren intérpretes o cargadores. WMI también puede lanzar calc.exe como prueba de ejecución remota.",
    eventos={4688, 1},
    agrupar_por=('vía', 'proceso_padre', 'proceso_hijo', 'línea_de_comandos', 'usuario'),
)
def remote_service_shell(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        parent, child = _exe(p.parent), _exe(p.image)
        if parent not in _REMOTE_SHELL_PARENTS:
            continue
        if child not in _REMOTE_SHELL_CHILDREN and (parent, child) != ("wmiprvse.exe", "calc.exe"):
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
    renombrada = re.fullmatch(r"([^\\]+)-[^\\]+-\d+-(?:stdin|stdout|stderr)", name)
    if renombrada and not name.startswith("psexesvc-"):
        return "PsExec con el servicio renombrado", "high"
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
      "Sysmon 17/18 y creación de pipes con cmd: canales conocidos de ejecución remota y suplantación.", eventos={17, 18, 7045, 1},
    agrupar_por=('pipe', 'proceso', 'indicador', 'línea_de_comandos', 'servicio'),
)
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
_BIND_SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "nc.exe", "ncat.exe"}


def _direccion(texto: str):
    try:
        ip = ipaddress.ip_address(texto)
    except ValueError:
        return None
    return getattr(ip, "ipv4_mapped", None) or ip


def _remota(ip) -> bool:
    return ip is not None and not (ip.is_loopback or ip.is_unspecified)


def _filtro_red(e: Event) -> bool:
    """WFP solo aporta detecciones RDP; Sysmon conserva todas sus conexiones."""
    return e.event_id != 5156 or e.get("DestinationPort", "DestPort") == "3389"


@rule("WLH-031", "Conexiones de red de shells y LOLBins", "medium", ["T1059", "T1105", "T1572"],
      "Sysmon 3: conexiones salientes públicas de intérpretes y LOLBins; acceso RDP por procesos inesperados, también 5156 local.", eventos={3, 5156}, filtro=_filtro_red)
def shell_network(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[tuple[str, str, str, str, str, str], list[Event]] = defaultdict(list)
    for e in events:
        is_sysmon = e.event_id == 3 and _is_sysmon(e)
        is_wfp = e.event_id == 5156 and (e.channel.lower() in ("security", "") or "security-auditing" in e.provider.lower())
        if not (is_sysmon or is_wfp):
            continue
        if is_wfp and e.get("Direction").lower() in {"inbound", "entrada", "%%14592"}:
            continue
        image = e.get("Image") if is_sysmon else e.get("Application")
        name = _exe(image)
        if not image or name in {"system", "[system process]"}:
            continue
        address, port = e.get("DestinationIp", "DestAddress"), e.get("DestinationPort", "DestPort")
        ip = _direccion(address)
        if ip is None:
            continue
        reason, severity = "", "medium"
        if is_sysmon and e.get("Initiated").lower() == "false":
            port = e.get("SourcePort")
            if name in _BIND_SHELLS and _remota(ip) and port not in {"", "5985", "5986"}:
                reason, severity = "intérprete que acepta conexiones remotas (bind shell)", "high"
        elif port == "3389" and not ip.is_unspecified and name not in _RDP_CLIENTS and (is_sysmon or ip.is_loopback):
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
                      mitre=["T1572"] if port == "3389" and not reason.endswith("(bind shell)") else ["T1059", "T1105"])


_DCOM_PROCESOS = {"explorer.exe", "mshta.exe", "mmc.exe", "excel.exe", "winword.exe", "outlook.exe", "visio.exe"}
_DCOM_OBJETOS = {
    "{49b2791a-b1ae-4c90-9b8e-e860ba07f889}": "MMC20.Application",
    "{9ba05972-f6a8-11cf-a442-00a0c90a8f39}": "ShellWindows",
    "{c08afd90-f2a1-11d1-8455-00a0c91f3880}": "ShellBrowserWindow",
    "{00024500-0000-0000-c000-000000000046}": "Excel.Application",
    "{0006f03a-0000-0000-c000-000000000046}": "Outlook.Application",
    "{00021a20-0000-0000-c000-000000000046}": "Visio",
}


@rule("WLH-038", "Ejecución remota por DCOM", "high", ["T1021.003"],
      "Activación de objetos DCOM y conexiones RPC de procesos de escritorio o PowerShell.",
      eventos={1, 3, 4688, ("System", 10016)})
def ejecucion_dcom(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        padre = p.event.get("ParentCommandLine")
        if (_exe(p.parent) == "svchost.exe" and _exe(p.image) in {"mshta.exe", "mmc.exe"}
                and re.search(r"(?:^|\s)-Embedding(?:\s|$)", p.command_line, re.I)
                and (not padre or re.search(r"(?:^|\s)-k\s+DcomLaunch(?:\s|$)", padre, re.I))):
            yield Hit([p.event], "Proceso activado por DCOM",
                      {"proceso": p.image, "proceso_padre": p.parent, "línea_de_comandos": _truncate(p.command_line)})
    for e in events:
        if e.event_id == 3 and _is_sysmon(e):
            ip = _direccion(e.get("DestinationIp"))
            if not _remota(ip):
                continue
            nombre = _exe(e.get("Image"))
            sentido = e.get("Initiated").lower()
            evidencia = {"proceso": e.get("Image"), "dirección": str(ip)}
            if sentido == "false" and nombre in _DCOM_PROCESOS:
                yield Hit([e], "Proceso de escritorio que acepta conexiones remotas (DCOM)", evidencia)
            elif (sentido == "true" and nombre in {"powershell.exe", "pwsh.exe"}
                  and e.get("DestinationPort") == "135" and ip.is_private and not ip.is_global
                  and not ip.is_multicast):
                yield Hit([e], "PowerShell conecta por RPC a otro equipo (WMI, DCOM o tareas remotas)",
                          evidencia, severity="medium")
        elif (e.event_id == 10016 and e.channel.lower() == "system"
              and "distributedcom" in e.provider.lower()
              and e.get("param2").lower() == "remote" and e.get("param3").lower() == "launch"):
            objeto = _DCOM_OBJETOS.get(e.get("param4").lower()) or _DCOM_OBJETOS.get(e.get("param5").lower())
            if objeto:
                yield Hit([e], f"Intento remoto de activar {objeto} por DCOM",
                          {"origen": e.get("param9"), "usuario": "\\".join((e.get("param6"), e.get("param7")))},
                          severity="medium")


_WINRM = "Microsoft-Windows-WinRM/Operational"
_RECONOCIMIENTO_WINRM = {
    "hostname.exe", "whoami.exe", "ipconfig.exe", "systeminfo.exe", "net.exe", "net1.exe",
    "nltest.exe", "quser.exe", "tasklist.exe", "netstat.exe", "arp.exe", "route.exe",
}


@rule("WLH-039", "PowerShell Remoting y WinRM", "medium", ["T1021.006"],
      "Procesos hijos de WinRM y sesiones WSMan entrantes.",
      eventos={1, 4688, (_WINRM, 91), (_WINRM, 169)})
def sesiones_winrm(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        hijo = _exe(p.image)
        if _exe(p.parent) in {"wsmprovhost.exe", "winrshost.exe"} and hijo and hijo not in _REMOTE_SHELL_CHILDREN:
            severidad = "medium" if hijo in _RECONOCIMIENTO_WINRM or _user_path(p.image) else "low"
            yield Hit([p.event], f"{hijo} lanzado desde una sesión WinRM",
                      {"proceso": p.image, "proceso_padre": p.parent, "usuario": p.user}, severity=severidad)
    sesiones = defaultdict(list)
    for e in events:
        if e.channel.lower() == _WINRM.lower() and e.event_id in {91, 169}:
            sesiones[e.computer.lower(), e.get("username").lower()].append(e)
    for evs in sesiones.values():
        for burst in _bursts(evs, cfg.window, 1):
            yield Hit(burst, "Sesión WinRM entrante",
                      {"usuario": burst[0].get("username"), "autenticación": sorted({
                          e.get("authenticationMechanism") for e in burst if e.get("authenticationMechanism")
                      })}, severity="low")


_RDP_RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
_RDP_CORE = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
_CLIENTES_MSTSCAX = (_RDP_CLIENTS - {"svchost.exe"}) | {"msrdcw.exe"}
_TSCLIENT = "\\\\tsclient\\"


@rule("WLH-040", "RDP sospechoso", "high", ["T1021.001", "T1572"],
      "Sesiones RDP desde loopback, unidades redirigidas y cargas inesperadas de mstscax.dll.",
      eventos={1, 7, 13, 4624, 4688, (_RDP_RCM, 1149), (_RDP_CORE, 131), (_RDP_CORE, 148)})
def rdp_sospechoso(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        if p.image.lower().startswith(_TSCLIENT):
            yield Hit([p.event], "Programa ejecutado desde una unidad del equipo cliente de RDP",
                      {"proceso": p.image, "usuario": p.user}, mitre=["T1021.001"])
    for e in events:
        if e.event_id == 148 and e.get("ChannelName").lower() == "ms_t120":
            yield Hit([e], "Canal virtual RDP MS_T120", {"canal_virtual": e.get("ChannelName")})
        origen, usuario = "", ""
        if e.event_id == 4624 and e.get("LogonType") == "10":
            origen, usuario = e.get("IpAddress"), _user(e)
        elif e.event_id == 1149 and e.channel.lower() == _RDP_RCM.lower():
            origen = e.get("Param3")
            usuario = "\\".join(filter(None, (e.get("Param2"), e.get("Param1"))))
        elif e.event_id == 131 and e.channel.lower() == _RDP_CORE.lower():
            origen = e.get("ClientIP")
            extremo = re.fullmatch(r"\[([^\]]+)\]:\d+|([^:]+):\d+", origen)
            if extremo:
                origen = extremo.group(1) or extremo.group(2)
        ip = _direccion(origen) if origen else None
        if ip is not None and ip.is_loopback:
            yield Hit([e], "Inicio de sesión RDP que llega por un túnel local",
                      {"origen": origen, "usuario": usuario})
        if not _is_sysmon(e):
            continue
        if (e.event_id == 13 and "\\explorer\\runmru\\" in e.get("TargetObject").lower()
                and _TSCLIENT in e.get("Details").lower()):
            yield Hit([e], "RunMRU registra una ejecución desde el equipo cliente de RDP",
                      {"clave": e.get("TargetObject"), "valor": _truncate(e.get("Details"))},
                      severity="medium", mitre=["T1021.001"])
        if e.event_id == 7 and _exe(e.get("ImageLoaded")) == "mstscax.dll":
            imagen = e.get("Image")
            if not imagen or _exe(imagen) in _CLIENTES_MSTSCAX:
                continue
            riesgo = (_user_path(imagen) or re.match(r"^[a-z]:\\programdata\\", ntpath.normpath(imagen), re.I)
                      or e.get("Signed").lower() == "false")
            if riesgo or _program_files_path(imagen):
                yield Hit([e], "Carga de mstscax.dll por un cliente RDP inesperado",
                          {"proceso": imagen, "dll": e.get("ImageLoaded")},
                          severity="high" if riesgo else "low", mitre=["T1021.001"])


_CREDENCIALES_REMOTAS = {
    "wmic.exe", "powershell.exe", "pwsh.exe", "psexec.exe", "psexec64.exe", "paexec.exe",
    "sc.exe", "schtasks.exe", "reg.exe", "winrs.exe", "mmc.exe",
}
_SHARES = r"hklm\system\currentcontrolset\services\lanmanserver\shares" + "\\"
_CODIGO_SMB = (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".hta")


@rule("WLH-041", "Otros indicios de ejecución remota", "high", ["T1021.002", "T1053.005", "T1570"],
      "Tareas de sesiones de red, copias SMB, servicios remotos, recursos compartidos, credenciales y xp_cmdshell.",
      eventos={1, 11, 13, ("Security", 4624), ("Security", 4648), ("Security", 4698),
               ("Security", 4702), ("Security", 5142), ("Application", 15281), ("Application", 15457)})
def otros_indicios_remotos(events: list[Event], cfg: Config) -> Iterator[Hit]:
    sesiones = {}
    for p in _processes(events):
        if (_exe(p.parent) == "services.exe"
                and re.fullmatch(r"(?:psexesvc|paexec[^\\]*|remcomsvc|csexecsvc)\.exe", _exe(p.image))):
            yield Hit([p.event], "Servicio de ejecución remota iniciado",
                      {"proceso": p.image, "proceso_padre": p.parent}, mitre=["T1021.002"])
    for e in events:
        equipo = e.computer.lower()
        if e.event_id == 4624 and e.get("LogonType") == "3":
            identificador = _registry_number(e.get("TargetLogonId"))
            if identificador:
                clave = equipo, identificador
                if _remota(_direccion(e.get("IpAddress"))):
                    sesiones[clave] = e
                else:
                    sesiones.pop(clave, None)
        elif e.event_id in {4698, 4702}:
            previa = sesiones.get((equipo, _registry_number(e.get("SubjectLogonId"))))
            if previa:
                tarea, ip = e.get("TaskName"), previa.get("IpAddress")
                usuario = e.get("SubjectUserName") or _user(previa)
                accion = "creada" if e.event_id == 4698 else "modificada"
                yield Hit([previa, e], f"Tarea {tarea} {accion} por {usuario} desde {ip}",
                          {"tarea": tarea, "usuario": usuario, "origen": ip}, mitre=["T1053.005"])
        elif e.event_id == 11 and _is_sysmon(e) and e.get("Image").lower() == "system":
            fichero = ntpath.normpath(e.get("TargetFilename")).lower()
            if fichero.startswith("c:\\windows\\") and fichero.endswith(_CODIGO_SMB):
                yield Hit([e], "Ejecutable copiado por SMB a la carpeta de Windows",
                          {"fichero": e.get("TargetFilename")}, mitre=["T1570"])
        elif e.event_id == 5142 or (e.event_id == 13 and _is_sysmon(e)):
            recurso = e.get("ShareName").rstrip("\\").rsplit("\\", 1)[-1] if e.event_id == 5142 else ""
            clave = e.get("TargetObject")
            if e.event_id == 13 and clave.lower().startswith(_SHARES):
                nombre = clave[len(_SHARES):]
                if "\\" not in nombre and nombre.lower() != "security":
                    recurso = nombre
            if recurso:
                yield Hit([e], f"Recurso compartido {recurso} creado", {"recurso": recurso},
                          severity="medium", mitre=["T1021.002"])
        elif e.event_id == 4648 and _exe(e.get("ProcessName")) in _CREDENCIALES_REMOTAS:
            servidor = e.get("TargetServerName").strip().lstrip("\\").lower().rstrip(".")
            ip = _direccion(servidor)
            if (servidor.split(".")[0] not in {"", "-", "localhost", equipo.split(".")[0]}
                    and (ip is None or _remota(ip))):
                yield Hit([e], "Credenciales explícitas para otro equipo",
                          {"destino": e.get("TargetServerName"), "proceso": e.get("ProcessName"),
                           "usuario": e.get("TargetUserName")}, severity="medium", mitre=["T1021.002"])
        elif (e.event_id in {15281, 15457} and e.channel.lower() == "application"
              and e.provider.lower().startswith("mssql")):
            datos = " ".join(e.data.values())
            if not re.search(r"\bxp_cmdshell\b", datos, re.I):
                continue
            if e.event_id == 15281:
                yield Hit([e], "Intento de usar xp_cmdshell bloqueado",
                          {"datos": _truncate(datos)}, severity="medium", mitre=["T1059"])
            elif (e.get("NewValue", "param3", "Data2") == "1"
                  or re.search(r"\bxp_cmdshell\b[^\r\n]*\b(?:to|a)\s+1\b", datos, re.I)):
                yield Hit([e], "Se habilitó xp_cmdshell", {"datos": _truncate(datos)}, mitre=["T1059"])




@rule("WLH-044", "Coerción de autenticación y barridos por SMB", "medium", ["T1187", "T1018", "T1135"],
      "Detecta acceso a pipes de coerción y patrones de red SMB.",
      eventos={3, 18, ("Security", 5145)})
def coercion_smb(events: list[Event], cfg: Config) -> Iterator[Hit]:
    conexiones, salientes, pipes = defaultdict(list), defaultdict(list), defaultdict(list)
    for e in events:
        if e.event_id == 5145:
            ip = _direccion(e.get("IpAddress"))
            pipe = _pipe_smb(e)
            if ip and _remota(ip) and _ipc(e) and pipe in {"spoolss", "efsrpc"}:
                yield Hit([e], "Acceso remoto a una pipe de coerción", {"origen": str(ip), "pipe": pipe})
            continue
        if not _is_sysmon(e) or e.get("Image").lower() != "system":
            continue
        equipo = e.computer.lower()
        if e.event_id == 18 and e.get("PipeName"):
            pipes[equipo].append(e)
        elif e.event_id == 3:
            sentido = e.get("Initiated").lower()
            if sentido not in {"true", "false"}:
                continue
            saliente = sentido == "true"
            if e.get("DestinationPort") == "445":
                ip = _direccion(e.get("DestinationIp" if saliente else "SourceIp"))
            elif not saliente and e.get("SourcePort") == "445":
                # Sysmon puede poner el extremo local primero en conexiones entrantes.
                ip = _direccion(e.get("DestinationIp"))
            else:
                continue
            if not ip or not _remota(ip):
                continue
            conexiones[equipo, str(ip)].append(e)
            if saliente:
                salientes[equipo].append(e)
    for (_, ip), evs in conexiones.items():
        for burst in _bursts(evs, timedelta(seconds=59, microseconds=999999), 2,
                             distinct=lambda e: e.get("Initiated").lower()):
            yield Hit(burst, "Autenticación SMB en los dos sentidos", {"extremo": ip})
    for grupos, campo, motivo in (
        (pipes, "PipeName", "Enumeración remota de named pipes"),
        (salientes, "DestinationIp", "Barrido SMB"),
    ):
        for evs in grupos.values():
            for burst in _bursts(evs, cfg.window, 5, distinct=lambda e: e.get(campo).lower()):
                yield Hit(burst, motivo, {"destinos": sorted({e.get(campo) for e in burst})})
