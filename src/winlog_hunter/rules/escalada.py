"""Reglas de escalada."""

from __future__ import annotations

import re

from .base import (Config, Event, Hit, Iterator, UNKNOWN, _INSTALLERS, _SHELLS,
                   _exe, _is_sysmon, _processes, _truncate, _windows_path, rule)


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
      "Secuestros por usuario, hijos sospechosos, DLL y ficheros en rutas de autoelevables.")
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
