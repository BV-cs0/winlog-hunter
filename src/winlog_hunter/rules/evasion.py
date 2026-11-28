"""Reglas de evasión."""

from __future__ import annotations

import re
import ntpath
import ipaddress
from datetime import timedelta
from collections import defaultdict
from urllib.parse import urlsplit
from functools import lru_cache

from .base import (Config, Event, Hit, Iterator, UNKNOWN, rule)
from .base import _exe, _is_sysmon, _processes, _truncate, _windows_path, decode_powershell
from .base import _ip_remota, _ipc, _maintenance_process, _pipe_smb, _program_files_path, _registry_number, _ruta_usuario


@rule("WLH-037", "Registro de eventos atacado", "high", ["T1562.002"],
      "Caída del servicio de registro de eventos, también tras una conexión remota a su canal.",
      eventos={1, 18, ("System", 7031), ("System", 7034), ("Security", 5145)})
def registro_eventos_atacado(events: list[Event], cfg: Config) -> Iterator[Hit]:
    conexiones = {}
    for e in events:
        equipo = e.computer.lower()
        if _is_sysmon(e):
            if e.event_id == 18 and e.get("PipeName").lower() == r"\eventlog" and e.get("Image").lower() == "system":
                conexiones[equipo] = e
            if (e.event_id != 1 or _exe(e.get("Image")) != "werfault.exe"
                    or not re.search(r"(?:^|\s)-u\s+-p\s+\d+\b", e.get("CommandLine"), re.I)):
                continue
            padre = e.get("ParentCommandLine")
            evidencia = {"proceso": e.get("Image"), "comando_padre": padre}
            if re.search(r"(?:^|\s)-s\s+EventLog(?:\s|$)", padre, re.I):
                yield Hit([e], "El servicio de registro de eventos se ha caído", evidencia)
            elif (_exe(e.get("ParentImage")) == "svchost.exe"
                  and re.search(r"(?:^|\s)-k\s+LocalServiceNetworkRestricted(?:\s|$)", padre, re.I)):
                previa = conexiones.get(equipo)
                if previa and timedelta(0) < e.timestamp - previa.timestamp < timedelta(minutes=2):
                    yield Hit([previa, e], "Caída del registro de eventos tras una conexión remota a su canal", evidencia)
        elif e.event_id == 5145 and _ipc(e) and _pipe_smb(e) == "eventlog" and _ip_remota(e.get("IpAddress")):
            yield Hit([e], "Acceso remoto a la pipe del registro de eventos",
                      {"origen": e.get("IpAddress"), "pipe": "eventlog"}, severity="medium")
        # La deshabilitación (7040) y la parada (7036) ya las trata WLH-034.
        elif e.event_id in (7031, 7034) and e.channel.lower() == "system" and e.get("param1").lower() in {
            "eventlog", "windows event log", "registro de eventos de windows",
        }:
            yield Hit([e], "El servicio de registro de eventos se ha caído", {"servicio": e.get("param1")})


_ORIGINAL_NAMES = {
    "cmd.exe": {"cmd.exe"}, "powershell.exe": {"powershell.exe"},
    "pwsh.exe": {"pwsh.exe"}, "rundll32.exe": {"rundll32.exe"},
    "regsvr32.exe": {"regsvr32.exe"}, "certutil.exe": {"certutil.exe"},
    "mshta.exe": {"mshta.exe"}, "wmic.exe": {"wmic.exe"},
    # Los metadatos de Sysinternals conservan el nombre del fuente en algunas versiones.
    "psexec.c": {"psexec.exe", "psexec64.exe", "psexec64a.exe"},
    "psexec.exe": {"psexec.exe", "psexec64.exe", "psexec64a.exe"},
    "procdump": {"procdump.exe", "procdump64.exe", "procdump64a.exe"},
    "procdump.exe": {"procdump.exe", "procdump64.exe", "procdump64a.exe"},
}
_SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe", "smss.exe", "wermgr.exe"}
_EXTENSIONES_DATOS = (".tmp", ".dat", ".jpg", ".png", ".txt", ".log")
# Los instaladores Inno Setup se ejecutan siempre como %TEMP%\is-XXXXX.tmp\<nombre>.tmp.
_INNO_SETUP = re.compile(r"\\is-[0-9a-z]{5}\.tmp\\[^\\]+\.tmp$", re.I)
_ACCESSIBILITY = {"sethc.exe", "osk.exe", "utilman.exe", "magnify.exe", "narrator.exe"}


@lru_cache(maxsize=8192)
def _ruta_disfraz(image: str) -> str:
    """Normaliza rutas repetidas sin conservar eventos ni datos de instancia."""
    return ntpath.normpath(image.strip('"')).lower()


@rule("WLH-023", "Binario renombrado o disfrazado", "medium", ["T1036.003", "T1036.005"],
      "Nombre original de una utilidad conocida distinto del ejecutable, o proceso de sistema fuera de su ruta.", eventos={4688, 1},
    agrupar_por=('indicador', 'proceso', 'nombre_original', 'usuario', 'línea_de_comandos'),
)
def masquerading(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        name = _exe(p.image)
        if not name:
            continue
        original = _exe(p.event.get("OriginalFileName")) if _is_sysmon(p.event) else ""
        reason, severity, mitre = "", "medium", ["T1036.003"]
        if original in _ORIGINAL_NAMES and name not in _ORIGINAL_NAMES[original]:
            reason = "nombre distinto al OriginalFileName de una utilidad conocida"
            if name in _ACCESSIBILITY and original in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
                reason, severity = "binario de accesibilidad sustituido por una shell", "high"
        path = _ruta_disfraz(p.image)
        misplaced = name in _SYSTEM_NAMES and not _windows_path(path)
        misplaced |= name == "explorer.exe" and not bool(re.fullmatch(r"[a-z]:\\windows\\explorer\.exe", path)) and not _windows_path(path, ("syswow64", "winsxs"))
        if (original.endswith(".exe") and original != name and _ruta_usuario(path)
                and "microsoft" in p.event.get("Company").lower()
                and name not in _ORIGINAL_NAMES.get(original, ())):
            reason = "ejecutable de Microsoft renombrado en una ruta de usuario"
            severity = "high" if original in _ORIGINAL_NAMES else "medium"
        if (name.endswith(_EXTENSIONES_DATOS) and not path.startswith("c:\\windows\\installer\\")
                and not _INNO_SETUP.search(path)):
            reason, severity = "proceso con extensión ajena a un ejecutable", "high"
        elif (_ruta_usuario(p.parent) and _exe(p.parent).endswith(_EXTENSIONES_DATOS)
              and not _INNO_SETUP.search(p.parent)):
            # El evento de creación del hijo también acredita la ejecución del padre.
            reason, severity = "proceso padre de usuario con extensión ajena a un ejecutable", "high"
        if misplaced:
            reason, severity, mitre = "nombre de proceso de sistema fuera de su ruta", "high", ["T1036.005"]
        if reason:
            yield Hit([p.event], f"{name}: {reason} en {p.event.computer or UNKNOWN}",
                      {"indicador": reason, "proceso": p.image, "nombre_original": original,
                       "usuario": p.user, "línea_de_comandos": _truncate(p.command_line)},
                      severity=severity, mitre=mitre)


_COMMAND_TOKEN = re.compile(r'^\s*(?:"([^"]+)"|([^\s"]+))\s*(.*)$', re.S)


def _command_target(image: str, command: str) -> tuple[str, str]:
    """Identifica la utilidad invocada sin interpretar argumentos impresos por echo."""
    name = _exe(image)
    if name == "cmd.exe":
        match = re.search(r"(?:^|\s)/[ck]\s+(.+)$", command, re.I)
        if not match:
            return name, command
        nested = match.group(1).strip()
        if nested.startswith('""') and nested.endswith('"'):
            nested = nested[1:-1]
        token = _COMMAND_TOKEN.match(nested)
        if token:
            name = _exe(token.group(1) or token.group(2))
            return name if name.endswith(".exe") else name + ".exe", token.group(3)
    return name, command


@rule("WLH-025", "Evasión e inhibición de recuperación por comandos", "high",
      ["T1490", "T1562.001", "T1562.004", "T1564.001", "T1070"],
      "Borrado de copias, desactivación de auditoría o defensas, ocultación y parada de EventLog.", eventos={4688, 1},
    agrupar_por=('indicador', 'proceso', 'usuario', 'línea_de_comandos', 'comando_de_eventlog'),
)
def defense_commands(events: list[Event], cfg: Config) -> Iterator[Hit]:
    processes = list(_processes(events))
    for p in processes:
        name, text = _command_target(p.image, p.command_line)
        text = text.lower()
        reason, technique, severity = "", "T1562.001", "high"
        related, eventlog_command = [p.event], ""
        if (name == "vssadmin.exe" and re.search(r"\bdelete\s+shadows\b", text) or
            name == "wmic.exe" and re.search(r"\bshadowcopy\b.*\bdelete\b", text) or
            name == "wbadmin.exe" and re.search(r"\bdelete\s+(?:catalog|systemstatebackup|backup)\b", text) or
            name == "bcdedit.exe" and re.search(r"/set\b.*(?:\brecoveryenabled\s+no\b|\bbootstatuspolicy\s+ignore(?:all|boot|shutdown)?failures\b)", text)):
            reason, technique = "eliminación de copias o inhibición de recuperación", "T1490"
        elif name == "wevtutil.exe" and re.search(r"(?:^|\s)(?:cl|clear-log)\s+|(?:^|\s)(?:sl|set-log)\s+.* /e:false\b", text):
            reason, technique = "borrado o desactivación de un registro de eventos", "T1070.001"
        elif name == "auditpol.exe" and re.search(r"/(?:clear|remove)\b|/set\b.* /(?:success|failure):disable\b", text):
            reason = "desactivación de auditoría"
        elif name == "netsh.exe":
            if re.search(r"\badvfirewall\s+set\b.*\bstate\s+off\b", text):
                reason, technique = "desactivación del firewall", "T1562.004"
            elif re.search(r"\binterface\s+portproxy\s+add\b", text):
                reason, technique, severity = "redirección de puertos con netsh", "T1090", "medium"
        elif name in {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}:
            text += "\n" + decode_powershell(p.command_line).lower()
            if re.search(r"\bset-mppreference\b[^;\r\n]*-disable\w+\s+(?:\$true|1)\b", text):
                reason = "desactivación de protección de Defender"
            elif re.search(r"\badd-mppreference\b[^;\r\n]*-exclusion(?:path|process|extension)\b", text):
                reason, severity = "adición de una exclusión de Defender", "medium"
        elif name == "attrib.exe" and re.search(r"(?:^|\s)\+h(?:\s|$)", text) and re.search(r"(?:^|\s)\+s(?:\s|$)", text):
            reason, technique, severity = "fichero marcado como oculto y de sistema", "T1564.001", "medium"
        elif (name == "attrib.exe" and re.search(r"(?:^|\s)\+h(?:\s|$)", text)
              and re.search(r'\.(?:exe|dll|ps1|bat|vbs|js|hta)(?:"|\s|$)', text)):
            reason, technique, severity = "fichero ejecutable o script marcado como oculto", "T1564.001", "medium"
        elif name in {"net.exe", "net1.exe"} and re.search(r'\bstop\s+"?eventlog\b', text):
            reason = "parada del servicio EventLog"
        elif name == "sc.exe" and re.search(r'\bconfig\s+"?eventlog"?\s+.*\bstart=\s*disabled\b', text):
            reason = "servicio EventLog deshabilitado"
        elif name == "taskkill.exe":
            if re.search(r"\bservices\s+eq\s+eventlog\b", text):
                reason = "terminación del proceso del servicio EventLog"
            else:
                pid = re.search(r"/pid\s+(\d+)\b", text)
                # El último inicio observado evita atribuir un PID reutilizado a EventLog.
                for prior in reversed(processes):
                    if not pid or prior.event.computer.lower() != p.event.computer.lower():
                        continue
                    if not (p.event.timestamp - cfg.window <= prior.event.timestamp <= p.event.timestamp):
                        continue
                    raw_pid = prior.event.get("ProcessId", "NewProcessId")
                    try:
                        prior_pid = int(raw_pid, 16 if raw_pid.lower().startswith("0x") else 10)
                    except ValueError:
                        continue
                    if prior_pid != int(pid.group(1)):
                        continue
                    if (_exe(prior.image) == "svchost.exe" and _windows_path(prior.image) and
                        re.search(r"(?:^|\s)-s\s+eventlog\b", prior.command_line, re.I)):
                        reason = "terminación del svchost identificado como EventLog"
                        related, eventlog_command = [prior.event, p.event], prior.command_line
                    break
        if reason:
            yield Hit(related, f"{reason.capitalize()} en {p.event.computer or UNKNOWN}",
                      {"indicador": reason, "proceso": p.image, "usuario": p.user,
                       "línea_de_comandos": _truncate(p.command_line),
                       "comando_de_eventlog": _truncate(eventlog_command)}, severity=severity, mitre=[technique])


def _defense_owner(image: str) -> bool:
    """Evita avisar de escrituras de mantenimiento de Windows y del propio Defender."""
    if _maintenance_process(image):
        return True
    if _windows_path(image) and _exe(image) in {"svchost.exe", "securityhealthservice.exe"}:
        return True
    return _exe(image) in {"msmpeng.exe", "mssense.exe", "mpcmdrun.exe"} and bool(re.match(
        r"^[a-z]:\\(?:program files\\windows defender(?: advanced threat protection)?\\|"
        r"programdata\\microsoft\\windows defender\\platform\\)", image, re.I))


@rule("WLH-029", "Desactivación de defensas en el registro", "high", ["T1562.001", "T1112"],
      "Sysmon 12/13: valores que debilitan UAC, auditoría PowerShell, Defender, LSA, firewall o seguridad de Office.", eventos={12, 13},
    agrupar_por=('clave', 'valor', 'proceso', 'operación', 'indicador'),
)
def registry_defenses(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id not in (12, 13) or not _is_sysmon(e):
            continue
        key, image, details = e.get("TargetObject"), e.get("Image"), e.get("Details")
        if not key or _defense_owner(image):
            continue
        key = key.lower()
        operation, number = e.get("EventType").lower(), _registry_number(details)
        deleted = operation in {"deletekey", "deletevalue"}
        reason, severity = "", "high"
        if e.event_id == 13 and not deleted:
            if key.endswith(r"\policies\system\enablelua") and number == 0:
                reason = "UAC deshabilitado"
            elif key.endswith(r"\powershell\scriptblocklogging\enablescriptblocklogging") and number == 0:
                reason = "registro de bloques PowerShell deshabilitado"
            elif key.endswith(r"\powershell\1\shellids\microsoft.powershell\executionpolicy") and details.lower() in {"bypass", "unrestricted"}:
                reason, severity = "política de ejecución PowerShell permisiva", "low"
            elif key.endswith(r"\environment\__pslockdownpolicy") or key.endswith(r"\session manager\environment\__pslockdownpolicy"):
                if number == 0:
                    reason, severity = "variable de restricción PowerShell deshabilitada", "medium"
            elif re.search(r"\\windows defender\\(?:real-time protection\\)?(?:disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring)$", key) and number == 1:
                reason = "protección de Defender deshabilitada"
            elif re.search(r"\\windows defender\\exclusions\\(?:paths|processes|extensions)\\[^\\].*$", key) and details:
                reason, severity = "exclusión de Defender añadida", "low"
            elif key.endswith(r"\securityproviders\wdigest\uselogoncredential") and number == 1:
                reason = "WDigest configurado para conservar credenciales"
            elif key.endswith(r"\control\lsa\runasppl") and number == 0:
                reason = "protección de LSASS deshabilitada"
            elif key.endswith(r"\control\terminal server\fdenytsconnections") and number == 0:
                reason, severity = "acceso RDP habilitado", "low"
            elif key.endswith(r"\control\terminal server\winstations\rdp-tcp\portnumber") and number is not None and number != 3389:
                reason, severity = "puerto RDP modificado", "low"
            elif re.search(r"\\services\\portproxy\\(?:v4tov4|v4tov6|v6tov4|v6tov6)\\tcp\\", key) and details:
                reason, severity = "redirección de puertos configurada en el registro", "low"
            elif re.search(r"\\(?:services\\sharedaccess\\parameters\\firewallpolicy|software\\policies\\microsoft\\windowsfirewall)\\(?:domainprofile|standardprofile|publicprofile)\\enablefirewall$", key) and number == 0:
                reason = "perfil de firewall deshabilitado"
            elif re.search(r"\\(?:software\\(?:policies\\)?microsoft\\office\\)\d+\.\d+\\(?:word|excel|powerpoint|access)\\security\\accessvbom$", key) and number == 1:
                reason, severity = "acceso programático al proyecto VBA habilitado", "low"
        elif e.event_id == 12 and deleted:
            if re.search(r"\\powershell\\scriptblocklogging(?:\\enablescriptblocklogging)?$", key):
                reason, severity = "configuración de registro de PowerShell eliminada", "medium"
            elif key.endswith(r"\environment\__pslockdownpolicy"):
                reason, severity = "variable de restricción PowerShell eliminada", "medium"
            elif re.search(r"\\explorer\\(?:runmru|recentdocs|comdlg32\\(?:opensavepidlmru|lastvisitedpidlmru))(?:\\|$)", key):
                # El propio Explorer limpia su historial cuando el usuario lo solicita.
                if not (_exe(image) == "explorer.exe" and re.fullmatch(r"[a-z]:\\windows\\(?:syswow64\\)?explorer\.exe", image, re.I)):
                    reason, severity = "historial MRU eliminado por un proceso ajeno a Explorer", "low"
        if reason:
            yield Hit([e], f"{reason.capitalize()} en {e.computer or UNKNOWN}",
                      {"indicador": reason, "clave": e.get("TargetObject"), "valor": _truncate(details),
                       "proceso": image, "operación": e.get("EventType")}, severity=severity)

@rule(
    "WLH-005",
    "Registro de eventos borrado",
    "critical",
    ["T1685.005"],
    "Se vació el registro de seguridad (1102) u otro registro (104): típico para borrar huellas.",
    eventos={104, 1102},
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


def _external_url(value: str) -> bool:
    """URL HTTP externa sin consultas DNS ni acceso a la red."""
    try:
        url = urlsplit(value)
        host = url.hostname or ""
        if url.scheme.lower() not in {"http", "https"} or not host or host.lower() == "localhost":
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            return "." in host and not host.lower().endswith((".local", ".lan", ".internal"))
    except ValueError:
        return False


# Redes de descarga de actualizaciones de Microsoft y Google. Edge, WebView2, Copilot y las apps
# hechas con Chromium (NVIDIA App, por ejemplo) descargan por BITS sus componentes desde aquí.
_UPDATE_CDNS = ("delivery.mp.microsoft.com", "windowsupdate.com", "update.microsoft.com", "gvt1.com", "dl.google.com")


def _update_download(image: str, url: str) -> bool:
    """Actualización rutinaria: un programa de Program Files que descarga de una CDN oficial de actualizaciones."""
    host = (urlsplit(url).hostname or "").lower() if url else ""
    oficial = any(host == cdn or host.endswith("." + cdn) for cdn in _UPDATE_CDNS)
    return oficial and _program_files_path(image)


@rule("WLH-036", "Alertas de Defender y trabajos BITS sospechosos", "high", ["T1562.001", "T1197"],
      "Detecciones de malware y desactivación de Defender; descargas BITS externas fuera del mantenimiento habitual.", eventos={3, 5001, 1006, 5007, 60, 1015, 59, 1116, 1117})
def defender_bits(events: list[Event], cfg: Config) -> Iterator[Hit]:
    jobs: dict[tuple[str, str], str] = {}
    for e in events:
        reason, severity, mitre = "", "high", ["T1562.001"]
        defender = e.provider.lower() == "microsoft-windows-windows defender" or e.channel.lower() == "microsoft-windows-windows defender/operational"
        bits = e.provider.lower() == "microsoft-windows-bits-client" or e.channel.lower() == "microsoft-windows-bits-client/operational"
        image = e.get("processPath", "ProcessPath", "ProcessName")
        url = e.get("url", "RemoteName", "remoteName", "RemoteUrl", "URL")
        if defender:
            if e.event_id in (1116, 1117, 1006, 1015):
                reason = "Defender notificó malware o una acción sobre la amenaza"
            elif e.event_id == 5001:
                reason = "protección en tiempo real de Defender desactivada"
            elif e.event_id == 5007:
                new, old = e.get("New Value", "NewValue"), e.get("Old Value", "OldValue")
                if new and new != old and re.search(r"\\exclusions\\(?:paths|processes|extensions)\\", new, re.I):
                    reason, severity = "configuración de exclusiones de Defender modificada", "low"
        elif bits and e.event_id in (3, 59, 60):
            job = (e.computer.lower(), e.get("jobId", "JobId", "Id"))
            if image and job[1]:
                jobs[job] = image
            image = image or jobs.get(job, "")
            if _maintenance_process(image) or (_windows_path(image) and _exe(image) == "svchost.exe") \
                    or _update_download(image, url):
                continue
            target = e.get("LocalName", "localName", "jobTitle", "JobTitle")
            executable = bool(re.search(r"\.(?:exe|dll|ps1|vbs|js|msi)(?:$|\?)", url or target, re.I))
            local_interpreter = _exe(url) in {"cmd.exe", "powershell.exe", "pwsh.exe", "regsvr32.exe", "rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe"}
            if _external_url(url) or (e.event_id == 3 and executable) or local_interpreter:
                reason, severity, mitre = "trabajo BITS con descarga externa o ejecutable", "medium" if executable and url else "low", ["T1197"]
        if reason:
            yield Hit([e], f"{reason.capitalize()} en {e.computer or UNKNOWN}",
                      {"indicador": reason, "amenaza": e.get("Threat Name", "ThreatName"), "proceso": image,
                       "url": _truncate(url), "trabajo": e.get("jobTitle", "JobTitle"),
                       "valor_nuevo": _truncate(e.get("New Value", "NewValue"))}, severity=severity, mitre=mitre)




_DRIVERS_VULNERABLES = set("""
    rwdrv.sys gdrv.sys rtcore64.sys dbutil_2_3.sys capcom.sys iqvw64e.sys asio.sys asio2.sys
    asio3.sys kprocesshacker.sys mhyprot2.sys zamguard64.sys aswarpot.sys gmer64.sys
    naldrv.sys procexp.sys
""".split())
_SERVICIO_IMAGEPATH = re.compile(r"^hklm\\system\\(?:currentcontrolset|controlset\d+)\\services\\[^\\]+\\imagepath$")


def _ruta_driver(ruta: str) -> str:
    ruta = ruta.strip().strip('"').lower()
    ruta = ruta.removeprefix("\\??\\").removeprefix("\\\\?\\")
    if ruta.startswith(("\\systemroot\\", "%systemroot%\\")):
        ruta = r"c:\windows" + ruta[ruta.index("\\", 1):]
    elif ruta.startswith("system32\\"):
        ruta = "c:\\windows\\" + ruta
    return ntpath.normpath(ruta)


@rule("WLH-045", "Drivers vulnerables o sospechosos", "high", ["T1068", "T1014", "T1562.001"],
      "Detecta cargas de drivers de riesgo y ficheros de driver escritos desde rutas de usuario.",
      eventos={6, 11, 13})
def drivers_sospechosos(events: list[Event], cfg: Config) -> Iterator[Hit]:
    escrituras, servicios = defaultdict(list), defaultdict(list)
    for e in events:
        if not _is_sysmon(e):
            continue
        equipo = e.computer.lower()
        if e.event_id == 6:
            ruta = e.get("ImageLoaded")
            nombre = _exe(ruta)
            if not nombre:
                continue
            vulnerable = (nombre in _DRIVERS_VULNERABLES or nombre == "vboxdrv.sys"
                          and not _ruta_driver(ruta).startswith("c:\\program files\\oracle\\"))
            if vulnerable or e.get("Signed").lower() == "false" or _ruta_usuario(_ruta_driver(ruta)):
                yield Hit([e], "Carga de driver vulnerable o sospechoso", {"driver": ruta})
            elif nombre in {"winring0x64.sys", "winring0.sys"}:
                yield Hit([e], "Carga de driver WinRing0", {"driver": ruta}, severity="medium")
        elif e.event_id == 11:
            ruta = _ruta_driver(e.get("TargetFilename"))
            if ruta.endswith(".sys") and _ruta_usuario(e.get("Image")):
                escrituras[equipo, ruta].append(e)
        elif e.event_id == 13 and _SERVICIO_IMAGEPATH.fullmatch(e.get("TargetObject").lower()):
            ruta = _ruta_driver(e.get("Details"))
            if ruta.endswith(".sys"):
                servicios[equipo, ruta].append(e)
    for clave, evs in escrituras.items():
        for e in evs:
            cambios = [s for s in servicios.get(clave, ()) if abs(s.timestamp - e.timestamp) <= cfg.window]
            evidencia = {"driver": e.get("TargetFilename"), "proceso": e.get("Image")}
            if cambios:
                evidencia["clave"] = cambios[0].get("TargetObject")
            yield Hit(sorted([e, *cambios], key=lambda x: x.timestamp),
                      "Driver escrito por un proceso en ruta de usuario", evidencia)
