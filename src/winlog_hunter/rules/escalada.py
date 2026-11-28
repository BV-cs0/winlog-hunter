"""Reglas de escalada."""

from __future__ import annotations

import ntpath
import re
from collections import defaultdict
from datetime import timedelta

from .base import (Config, Event, Hit, Iterator, UNKNOWN, _INSTALLERS, _SHELLS,
                   _exe, _is_sysmon, _processes, _truncate, _windows_path, rule)
from .base import (_LOOPBACK, _REMOTE_PIPES, _TOKEN_COMANDO, _argumento, _bajo_windows,
                   _debugger_process, _ipc, _maintenance_process, _pipe_smb,
                   _program_files_path, _ruta_usuario)


# ATT&CK T1548.002: secuestros por usuario y carga lateral en autoelevables.
_UAC_CLASSES = re.compile(
    r"^(?:(?:hkcu|hku\\[^\\]+)\\software\\classes|hku\\[^\\]+_classes)\\"
    r"(?:ms-settings|mscfile|exefile|folder|launcher\.systemsettings)\\shell\\open\\command(?:\\|$)", re.I)
_UAC_APP_PATHS = re.compile(
    r"^(?:hkcu|hku\\[^\\]+)\\software\\microsoft\\windows\\currentversion\\app paths\\[^\\]+(?:\\\(default\))?$", re.I)
_UAC_ENV = re.compile(r"^(?:hkcu|hku\\[^\\]+)\\environment\\(?:windir|systemroot)$", re.I)
_AUTO_PARENTS = {
    "fodhelper.exe", "computerdefaults.exe", "eventvwr.exe", "sdclt.exe", "slui.exe",
    "wsreset.exe", "compmgmtlauncher.exe", "changepk.exe", "cmstp.exe", "perfmon.exe",
}
_AUTO_DLL = {"sysprep.exe", "cliconfg.exe", "migwiz.exe", "mcx2prov.exe"}
_AUTO_DIRS = re.compile(r"^[a-z]:\\windows\\(?:system32|syswow64)\\(?:sysprep|oobe|migwiz)\\", re.I)
_MOCK_WINDOWS = re.compile(r"^[a-z]:\\windows +\\(?:system32|syswow64)\\", re.I)


_DLL_AUTOELEVACION = set("""
    dismcore.dll wow64log.dll osksupport.dll mscoree.dll gdiplus.dll elsext.dll
    comctl32.dll cryptbase.dll ntwdblib.dll wdscore.dll
""".split())
_COM_ELEVADO = re.compile(r"/processid:\s*\{(?:3e5fc7f9-9a51-4367-9063-a120244fbec7|"
                         r"d2e7041b-2927-42fb-8e9f-7ce93b6dc937)\}", re.I)
_MANIFEST = _AUTO_PARENTS | _AUTO_DLL | {"wscript.exe", "pkgmgr.exe", "dism.exe", "wusa.exe"}


# WinPwnage invocado con sus opciones, no el nombre citado dentro de un script.
_WINPWNAGE = re.compile(r'(?:^|[\s\\/"])winpwnage(?:\.py|\.exe)?"?(?:\s+--?[a-z]|\s*$)', re.I)


@rule("WLH-022", "Posible bypass de UAC", "high", ["T1548.002"],
      "Secuestros por usuario, hijos sospechosos, DLL y ficheros en rutas de autoelevables.", eventos={1, 7, 11, 12, 13, 4688},
    agrupar_por=('indicador', 'proceso', 'proceso_padre', 'clave', 'valor', 'fichero', 'línea_de_comandos'),
)
def uac_bypass(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if not _is_sysmon(e):
            continue
        reason, severity = "", "high"
        key, image = e.get("TargetObject"), e.get("Image")
        if e.event_id in (12, 13) and e.get("EventType").lower() not in ("deletekey", "deletevalue"):
            if (e.event_id == 13 and _exe(image) == "dllhost.exe"
                    and key.lower().endswith(r"\app paths\cmmgr32.exe\profileinstallpath")):
                reason, severity = "ruta de instalación de perfil cambiada por COM", "medium"
            elif _UAC_CLASSES.search(key) or _UAC_ENV.search(key):
                reason = "secuestro de asociación o entorno de autoelevación por usuario"
            elif _UAC_APP_PATHS.search(key):
                reason, severity = "registro de App Paths por usuario", "medium"
        elif e.event_id == 7 and _exe(e.get("ImageLoaded")) == "wow64log.dll":
            reason = "carga de wow64log.dll"
        elif e.event_id == 7 and _exe(image) in _AUTO_DLL and _windows_path(image, ("system32", "syswow64", "winsxs", "ehome")):
            dll = e.get("ImageLoaded")
            if dll and (e.get("Signed").lower() == "false" or not _windows_path(dll)):
                reason = "autoelevable carga una DLL sin firma o fuera de las carpetas de sistema"
                severity = "high" if e.get("Signed").lower() == "false" else "medium"
        elif e.event_id == 11:
            target = e.get("TargetFilename")
            if _MOCK_WINDOWS.search(target):
                reason = "escritura en una carpeta que imita a Windows con un espacio"
            elif _AUTO_DIRS.search(target) and target.lower().endswith((".dll", ".exe")) and not _INSTALLERS.match(image):
                reason = "binario escrito en un directorio de autoelevación"
            elif (_exe(target).removesuffix(".manifest") in _MANIFEST and target.lower().endswith(".manifest")
                  and (_ruta_usuario(target) or _bajo_windows(target))
                  and not (_INSTALLERS.match(image) or _maintenance_process(image))):
                reason, severity = "manifest de autoelevable escrito fuera de una instalación", "medium"
            elif _exe(target) in _DLL_AUTOELEVACION and _ruta_usuario(target):
                reason, severity = "DLL de autoelevación escrita en ruta de usuario", "medium"
        if reason:
            yield Hit([e], f"Posible bypass de UAC: {reason} en {e.computer or UNKNOWN}",
                      {"indicador": reason, "proceso": image, "clave": key,
                       "valor": _truncate(e.get("Details")), "fichero": e.get("ImageLoaded", "TargetFilename")},
                      severity=severity)
    for p in _processes(events):
        parent, child = _exe(p.parent), _exe(p.image)
        reason, severity = "", "high"
        unusual_msc = parent == "mmc.exe" and bool(re.search(
            r'(?:[a-z]:\\(?:users|temp|programdata)\\|%temp%)[^"\r\n]*\.msc\b',
            p.event.get("ParentCommandLine"), re.I))
        if (parent in _AUTO_PARENTS or unusual_msc) and _windows_path(p.parent):
            if child in _SHELLS:
                reason = "autoelevable lanzó una shell o intérprete"
            elif p.image and not _windows_path(p.image):
                reason, severity = "autoelevable lanzó un binario fuera del sistema", "medium"
        comando = p.command_line
        if parent == "dllhost.exe" and _COM_ELEVADO.search(p.event.get("ParentCommandLine")):
            if child in _SHELLS:
                reason = "COM elevado lanzó una shell"
            elif p.image and not _bajo_windows(p.image):
                reason, severity = "COM elevado lanzó un binario fuera de Windows", "medium"
        xml = _argumento(comando, {"pkgmgr.exe": "/n:", "dism.exe": "/apply-unattend:"}[child]) if child in {"pkgmgr.exe", "dism.exe"} else ""
        if xml.lower().endswith(".xml") and _ruta_usuario(xml):
            reason, severity = "paquete instalado con XML de usuario", "high"
        if child in _SHELLS and parent in {"pkgmgr.exe", "dism.exe", "werfault.exe", "wermgr.exe"}:
            reason, severity = "proceso de sistema lanzó una shell", "high"
        if child == "wusa.exe":
            destino = _argumento(comando, "/extract:").lower().rstrip("\\")
            if destino == r"c:\windows" or _bajo_windows(destino):
                reason, severity = "wusa extrae bajo Windows", "high"
        if child == "makecab.exe":
            argumentos = _TOKEN_COMANDO.findall(comando)
            if len(argumentos) > 1:
                archivo = (argumentos[1][0] or argumentos[1][1]).lower()
                if (_windows_path(archivo, ("system32",)) and archivo.endswith((".exe", ".dll", ".sys"))
                        or archivo.endswith(".manifest")):
                    reason, severity = "makecab empaqueta un binario de sistema o un manifest", "medium"
        if (re.fullmatch(r"(?:uacme|akagi[^\\]*)\.exe", child)
                or re.fullmatch(r"(?:uacme|akagi[^\\]*)\.exe", parent)
                or _WINPWNAGE.search(comando) or _WINPWNAGE.search(p.event.get("ParentCommandLine"))):
            reason, severity = "herramienta conocida de bypass de UAC", "high"
        if not reason and child == "cmstp.exe" and re.search(r"(?:^|\s)/(?:s|au)(?:\s|$)", p.command_line, re.I) and re.search(r"\.(?:inf|ini)\b", p.command_line, re.I):
            archivos = [a or b for a, b in _TOKEN_COMANDO.findall(comando)
                        if (a or b).lower().endswith((".inf", ".ini"))]
            reason = "cmstp con instalación silenciosa de un INF o INI"
            severity = "high" if any(_ruta_usuario(a) for a in archivos) else "medium"
        if reason:
            yield Hit([p.event], f"Posible bypass de UAC: {reason} en {p.event.computer or UNKNOWN}",
                      {"indicador": reason, "proceso": p.image, "proceso_padre": p.parent,
                       "línea_de_comandos": _truncate(p.command_line)}, severity=severity)


@rule("WLH-034", "Privilegios y ajustes peligrosos del sistema", "medium", ["T1134", "T1553.006", "T1562"],
      "Privilegios sensibles fuera de procesos habituales, arranque inseguro, retirada de auditoría o parada de EventLog.", eventos={7040, 4673, 4719, 4985, 4826, 7036, 25, 4703})
def system_privileges(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        security = e.channel.lower() == "security" or "security-auditing" in e.provider.lower()
        reason, severity, mitre = "", "medium", ["T1134"]
        image = e.get("ProcessName", "Image")
        related_events = [e]
        if security and e.event_id in (4703, 4673):
            privileges = e.get("EnabledPrivilegeList") if e.event_id == 4703 else e.get("PrivilegeList")
            sensitive = sorted(set(re.findall(r"Se(?:Debug|Tcb|Impersonate)Privilege", privileges, re.I)))
            if sensitive and image and not _windows_path(image) and not _debugger_process(image) and not _maintenance_process(image):
                if not re.fullmatch(r"[a-z]:\\windows\\(?:syswow64\\)?explorer\.exe", image, re.I):
                    reason = "privilegios sensibles habilitados" if e.event_id == 4703 else "uso de un servicio con privilegios sensibles"
                    severity = "low" if _program_files_path(image) or e.event_id == 4673 else "medium"
        elif security and e.event_id == 4826:
            labels = {"KernelDebug": "depuración de kernel", "TestSigning": "firma de prueba", "DisableIntegrityChecks": "comprobación de integridad desactivada"}
            enabled = [label for key, label in labels.items() if e.get(key).lower() in {"%%1842", "yes", "true", "1", "enabled"}]
            if enabled:
                reason, mitre = "arranque con " + ", ".join(enabled), ["T1553.006"]
        elif security and e.event_id == 4719 and re.search(r"success removed|failure removed|éxitos quitados|errores quitados|%%8448|%%8450", e.get("AuditPolicyChanges"), re.I):
            reason, severity, mitre = "retirada de auditoría de seguridad", "high", ["T1562.002"]
        elif e.event_id in (7036, 7040) and e.channel.lower() == "system" and e.provider.lower() in {"service control manager", ""}:
            service = e.get("param1", "ServiceName").lower()
            stopped = e.get("param2", "State").lower() in {"stopped", "detenido", "parado"}
            disabled = e.get("param3", "StartType").lower() in {"disabled", "deshabilitado"}
            if service in {"eventlog", "windows event log", "registro de eventos de windows"} and ((e.event_id == 7036 and stopped) or (e.event_id == 7040 and disabled)):
                reason, severity, mitre = "servicio de registro de eventos parado o deshabilitado", "high", ["T1562.002"]
        elif security and e.event_id == 4985 and e.get("ProcessId", "ProcessID"):
            def pid(value):
                try:
                    return int(value, 16 if value.lower().startswith("0x") else 10)
                except ValueError:
                    return None
            process_id = pid(e.get("ProcessId", "ProcessID"))
            related = [x for x in events if x.computer.lower() == e.computer.lower() and _is_sysmon(x) and x.event_id == 25
                       and abs((x.timestamp - e.timestamp).total_seconds()) <= cfg.window.total_seconds()
                       and process_id is not None and pid(x.get("ProcessId")) == process_id]
            if related:
                reason, severity, mitre = "transacción NTFS junto a manipulación de la misma imagen de proceso", "high", ["T1055.013"]
                related_events = sorted([e, related[0]], key=lambda x: x.timestamp)
        if security and e.event_id == 4985 and not reason and image:
            if not _bajo_windows(image) and not _program_files_path(image):
                reason, mitre = "transacción NTFS desde un proceso fuera de Windows", ["T1055.013"]
        if reason:
            yield Hit(related_events, f"{reason.capitalize()} en {e.computer or UNKNOWN}",
                      {"indicador": reason, "proceso": image, "privilegios": e.get("EnabledPrivilegeList", "PrivilegeList"),
                       "usuario": e.get("SubjectUserName"), "cambio": e.get("AuditPolicyChanges"),
                       "pid": e.get("ProcessId", "ProcessID")}, severity=severity, mitre=mitre)


_PIPES_WINDOWS = set(_REMOTE_PIPES) | set("""
    srvsvc wkssvc samr lsarpc netlogon spoolss winreg eventlog browser epmapper
    ntsvcs initshutdown lsass protected_storage efsrpc
""".split())
_USCHEDULER = re.compile(r"\\windowsupdate\\orchestrator\\uscheduler\\.+\\(?:cmdline|startarg|pausearg)$")
_COMANDO_SHELL = re.compile(r"\b(?:" + "|".join(re.escape(x.removesuffix(".exe"))
                              for x in sorted(_SHELLS | {"whoami.exe"})) + r")(?:\.exe)?\b")
_COLA_REGISTRO = re.compile(r"\\print\\printers\\[^\\]+\\(?:spooldirectory|copyfiles\\[^\\]+\\module)$")


@rule("WLH-042", "Escalada local de privilegios", "high", ["T1068", "T1134.001"],
      "Detecta suplantación local, cambios sensibles y ejecución mediante tareas.",
      eventos={1, 3, 7, 11, 13, 4688, ("Security", 4624), ("Security", 4648), ("Security", 5145)})
def escalada_local(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        reason, severity = "", "high"
        image = e.get("Image", "ProcessName")
        nombre = _exe(image)
        clave = e.get("TargetObject").lower()
        fichero = e.get("ImageLoaded", "TargetFilename").lower()
        ip = e.get("IpAddress")
        if e.channel.lower() == "security":
            usuario = e.get("TargetUserName").lower()
            if e.event_id == 4624 and e.get("LogonType") == "3" and ip in _LOOPBACK:
                if usuario == "anonymous logon" and e.get("LogonProcessName").strip().lower() == "ntlmssp":
                    reason, severity = "inicio NTLM anónimo desde loopback", "medium"
                elif usuario and not usuario.endswith("$") and e.get("AuthenticationPackageName").lower() == "kerberos":
                    reason, severity = "inicio Kerberos de usuario desde loopback", "medium"
            if (e.event_id == 5145 and ip in _LOOPBACK and _ipc(e) and e.get("SubjectUserName").endswith("$")
                    and _pipe_smb(e) and _pipe_smb(e) not in _PIPES_WINDOWS):
                reason, severity = "acceso SMB local a una pipe no habitual", "medium"
            if e.event_id == 4648 or e.event_id == 4624 and e.get("LogonProcessName").strip().lower() == "advapi":
                if (nombre in {"w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "sqlservr.exe"}
                        or re.fullmatch(r"tomcat[^\\]*\.exe", nombre)
                        or nombre == "java.exe" and re.search(r"\\(?:apache[^\\]* )?tomcat[^\\]*\\", image, re.I)):
                    reason = "credenciales explícitas desde un servidor"
        elif _is_sysmon(e):
            if (e.event_id == 3 and _ruta_usuario(image) and e.get("SourceIp") in _LOOPBACK
                    and e.get("DestinationIp") in _LOOPBACK
                    and {e.get("DestinationPort"), e.get("SourcePort")} & {"5985", "5986"}):
                reason = "WinRM en loopback desde un programa de usuario"
            elif e.event_id == 7 and nombre == "spoolsv.exe" and e.get("Signed").lower() == "false":
                if r"\spool\drivers" + "\\" in fichero and fichero.endswith(".dll"):
                    reason = "la cola de impresión cargó una DLL sin firma"
            elif e.event_id == 11 and nombre == "spoolsv.exe" and fichero.endswith((".dll", ".exe")):
                if not ntpath.normpath(fichero).startswith(("c:\\windows\\system32\\spool\\", "c:\\windows\\temp\\")):
                    reason = "la cola de impresión escribió un binario fuera de su directorio"
            elif e.event_id == 13:
                if (nombre == "spoolsv.exe" and re.search(
                        r"\\windows nt\\currentversion\\ports\\[a-z]:\\.+\.(?:dll|exe)$", clave)
                        or _COLA_REGISTRO.search(clave)):
                    reason = "configuración sensible de la cola de impresión"
                elif _USCHEDULER.search(clave) and _COMANDO_SHELL.search(e.get("Details").lower()):
                    reason = "Windows Update configurado para ejecutar una shell"
                elif clave.endswith(r"\symboliclinkvalue") and image and not _bajo_windows(image):
                    reason = "enlace simbólico de registro creado fuera de Windows"
        if reason:
            yield Hit([e], reason, {"proceso": image, "clave": clave, "fichero": fichero, "origen": ip},
                      severity=severity)

    tareas = defaultdict(list)
    for p in _processes(events):
        exe = _exe(p.image)
        if (exe in _SHELLS | {"whoami.exe"} and _ruta_usuario(p.parent)
                and p.user.lower() in {"system", "sistema", r"nt authority\system", r"nt authority\sistema"}):
            yield Hit([p.event], "Shell como SYSTEM desde un programa de usuario",
                      {"proceso": p.image, "proceso_padre": p.parent})
        if exe != "schtasks.exe":
            continue
        comando = p.command_line
        tarea = _argumento(comando, "/tn ").lower().lstrip("\\")
        padre = p.event.get("ParentProcessGuid", "ParentProcessId") or p.parent.lower()
        clave = (p.event.computer.lower(), padre, tarea)
        xml = _argumento(comando, "/xml ")
        if re.search(r"\s/create\b", comando, re.I) and _ruta_usuario(xml):
            tareas[clave].append((p.event, xml, False))
        elif tarea and padre and re.search(r"\s/run\b", comando, re.I):
            anteriores = tareas.get(clave)
            if anteriores:
                anterior, ruta, ejecutada = anteriores[-1]
                if not ejecutada and p.event.timestamp - anterior.timestamp < timedelta(minutes=5):
                    anteriores[-1] = (anterior, ruta, True)
                    yield Hit([anterior, p.event], "Tarea creada desde XML de usuario y ejecutada",
                              {"tarea": tarea, "fichero": ruta})
    for anteriores in tareas.values():
        for evento, ruta, ejecutada in anteriores:
            if not ejecutada:
                yield Hit([evento], "Tarea creada desde XML de usuario", {"fichero": ruta}, severity="medium")
