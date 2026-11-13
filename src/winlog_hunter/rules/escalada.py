"""Reglas de escalada."""

from __future__ import annotations

import re

from .base import (Config, Event, Hit, Iterator, UNKNOWN, _INSTALLERS, _SHELLS,
                   _exe, _is_sysmon, _processes, _truncate, _windows_path, rule)
from .base import _debugger_process, _maintenance_process, _program_files_path


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
            if _UAC_CLASSES.search(key) or _UAC_ENV.search(key):
                reason = "secuestro de asociación o entorno de autoelevación por usuario"
            elif _UAC_APP_PATHS.search(key):
                reason, severity = "registro de App Paths por usuario", "medium"
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
        if child == "cmstp.exe" and re.search(r"(?:^|\s)/(?:s|au)(?:\s|$)", p.command_line, re.I) and re.search(r"\.inf\b", p.command_line, re.I):
            reason, severity = "cmstp con instalación silenciosa de un INF", "medium"
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
        if reason:
            yield Hit(related_events, f"{reason.capitalize()} en {e.computer or UNKNOWN}",
                      {"indicador": reason, "proceso": image, "privilegios": e.get("EnabledPrivilegeList", "PrivilegeList"),
                       "usuario": e.get("SubjectUserName"), "cambio": e.get("AuditPolicyChanges"),
                       "pid": e.get("ProcessId", "ProcessID")}, severity=severity, mitre=mitre)
