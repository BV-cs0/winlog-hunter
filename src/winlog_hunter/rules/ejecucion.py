"""Reglas de ejecución."""

from __future__ import annotations

import re

from .base import _browser_root, _bursts, _debugger_process, _is_sysmon, _program_files_path, _user_path, _windows_path

from .base import (Config, ENCODED, Event, Hit, Iterator, UNKNOWN, _LOLBINS, _OFFICE, _POWERSHELL, _PS_INDICATORS, _SCRIPT_BLOCK_INDICATORS, _SHELLS, _exe, _processes, _truncate, decode_powershell, rule)


# Referencia: LOLBAS. Se conservan intactas las selecciones anteriores.
_MORE_LOLBINS = [
    ("pcalua.exe", r"(?:^|\s)-a\s+", "T1202", "ejecución indirecta con pcalua"),
    # Los dos operandos pueden tener cualquier extensión: XML/XSL es el contenido.
    ("msxsl.exe", r'^\s*(?:"[^"]+"|\S+)\s+(?:"[^"]+"|\S+)\s+(?:"[^"]+"|\S+)', "T1220", "transformación XSL con posible ejecución de scripts"),
    ("desktopimgdownldr.exe", r"/lockscreenurl(?:\s|:)", "T1105", "descarga de imagen remota"),
    ("ftp.exe", r"(?:^|\s)-s:", "T1105", "ejecución de comandos FTP desde fichero"),
    ("hh.exe", r"(?:https?://|\\\\)[^\r\n]*\.chm\b", "T1218.001", "ayuda CHM remota"),
    ("wuauclt.exe", r"/runhandlercomserver\b", "T1218", "carga de un manejador COM"),
    ("rundll32.exe", r"(?:advpack(?:\.dll)?\s*,\s*(?:launchinfsection|registerocx)|zipfldr(?:\.dll)?\s*,\s*routethecall|pcwutl(?:\.dll)?\s*,\s*launchapplication|shell32(?:\.dll)?\s*,\s*shellexec_rundll|\.cpl\b)", "T1218.011", "ejecución indirecta mediante DLL del sistema"),
    ("vshadow.exe", r"(?:^|\s)-exec(?:=|\s)", "T1218", "ejecución a través de vshadow"),
    ("msiexec.exe", r"https?://|(?:^|\s)/y(?:\s|$)", "T1218.007", "instalación remota o registro de DLL"),
    ("wmic.exe", r"/format:\s*[\"']?[^\r\n]*\.xsl\b", "T1220", "ejecución de XSL mediante WMI"),
    # Motor de script forzado sobre un fichero que no es un script (.ico, .txt, .log...).
    ("wscript.exe", r"/e:(?:vbs|vbscript|jscript|javascript)\b\s+\"?[^\s\"]+\.(?!(?:vbs|vbe|js|jse|wsf|wsh)\b)\w+", "T1027",
     "motor de script forzado sobre un fichero que no es un script"),
    ("cscript.exe", r"/e:(?:vbs|vbscript|jscript|javascript)\b\s+\"?[^\s\"]+\.(?!(?:vbs|vbe|js|jse|wsf|wsh)\b)\w+", "T1027",
     "motor de script forzado sobre un fichero que no es un script"),
    ("control.exe", r"(?:[a-z]:\\(?!windows\\(?:system32|syswow64)\\)|\\\\|%[^%]+%)[^\r\n]*\.cpl\b", "T1218.002", "panel de control fuera del sistema"),
]
_MORE_LOLBINS = [(name, re.compile(pattern, re.I), [mitre], label)
                 for name, pattern, mitre, label in _MORE_LOLBINS]

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


@rule(
    "WLH-011",
    "Uso malicioso de binario del sistema (LOLBin)",
    "high",
    ["T1218"],
    "Binarios legítimos con argumentos de ejecución indirecta, carga de scripts o descarga remota.",
)
def lolbins(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        exe = _exe(p.image)
        candidates = _LOLBINS + _MORE_LOLBINS
        if _exe(p.parent) == "hh.exe":
            yield Hit([p.event], f"hh.exe lanzó {exe} en {p.event.computer or UNKNOWN}",
                      {"proceso_padre": p.parent, "proceso_hijo": p.image,
                       "línea_de_comandos": _truncate(p.command_line)},
                      mitre=["T1218.001"], severity="high" if exe in _SHELLS else "medium")
            continue
        if exe in _SHELLS and (
            _exe(p.parent) == "msxsl.exe" or
            _exe(p.parent) == "wuauclt.exe" and re.search(r"/runhandlercomserver\b", p.event.get("ParentCommandLine"), re.I)
        ):
            yield Hit([p.event], f"{_exe(p.parent)} lanzó {exe} en {p.event.computer or UNKNOWN}",
                      {"proceso_padre": p.parent, "proceso_hijo": p.image,
                       "comando_del_padre": _truncate(p.event.get("ParentCommandLine")),
                       "línea_de_comandos": _truncate(p.command_line)},
                      mitre=["T1220"] if _exe(p.parent) == "msxsl.exe" else ["T1218"])
            continue
        for name, pattern, mitre, technique in candidates:
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
                    severity="medium" if name in {"pcalua.exe", "msxsl.exe", "ftp.exe", "msiexec.exe"} else "high",
                )
                break


_SERVER_PARENTS = {"w3wp.exe", "httpd.exe", "tomcat.exe", "tomcat8.exe", "tomcat9.exe",
                   "tomcat10.exe", "php-cgi.exe", "nginx.exe", "sqlservr.exe", "spoolsv.exe", "msiexec.exe"}


@rule("WLH-024", "Shell lanzada por un servidor o servicio", "high",
      ["T1505.003", "T1190", "T1021.003"],
      "Servidores web, SQL, instalador o spooler abren intérpretes; activación DCOM inusual.")
def server_shell(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        parent, child = _exe(p.parent), _exe(p.image)
        # Excel ya pertenece a WLH-012; WMI/WinRM a WLH-018.
        parent_command = p.event.get("ParentCommandLine")
        embedded_parent = parent in {"mmc.exe", "explorer.exe"} and bool(re.search(
            r"(?:^|\s)[-/]embedding(?:\s|$)", parent_command, re.I)) and not re.search(r"/factory,", parent_command, re.I)
        shell = child in _SHELLS and (parent in _SERVER_PARENTS or parent == "smss.exe" or embedded_parent)
        # explorer.exe /factory,{CLSID} -Embedding lo lanza Windows a diario: no es DCOM remoto.
        activation = parent == "svchost.exe" and child in {"mmc.exe", "explorer.exe", "excel.exe"} and bool(re.search(
            r"(?:^|\s)[-/]embedding(?:\s|$)", p.command_line, re.I)) and not re.search(r"/factory,", p.command_line, re.I)
        if not (shell or activation):
            continue
        yield Hit([p.event], f"{parent} lanzó {child} en {p.event.computer or UNKNOWN}",
                  {"proceso_padre": p.parent, "proceso_hijo": p.image, "usuario": p.user,
                   "línea_de_comandos": _truncate(p.command_line),
                   "comando_del_padre": _truncate(p.event.get("ParentCommandLine"))},
                  # Las acciones personalizadas de instaladores lanzan cmd/PowerShell a menudo.
                  severity="low" if parent == "msiexec.exe" else "medium" if activation else "high",
                  mitre=["T1021.003"] if activation or embedded_parent else
                        ["T1505.003", "T1190"] if parent in {"w3wp.exe", "httpd.exe", "php-cgi.exe", "nginx.exe"} else ["T1059"])


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


def _routine_thread_source(source: str, target: str) -> bool:
    """Orígenes habituales de hilos remotos; las excepciones requieren su ruta habitual."""
    name = _exe(source)
    if source.lower() == "system":
        return True
    if _windows_path(source) and name in {"csrss.exe", "wininit.exe", "sysmon.exe", "sysmon64.exe", "sysmon64a.exe"}:
        return True
    if _windows_path(source) and name == "svchost.exe" and _windows_path(target):
        return True
    if re.fullmatch(r"[a-z]:\\windows\\sysmon(?:64a?|)\.exe", source, re.I):
        return True
    if _debugger_process(source):
        return True
    browser = _browser_root(source)
    if browser and browser == _browser_root(target):
        return True
    # Defender actualiza su motor tanto en Program Files como en ProgramData.
    if name in {"msmpeng.exe", "mssense.exe"} and re.match(
        r"^[a-z]:\\(?:program files\\windows defender(?: advanced threat protection)?\\|"
        r"programdata\\microsoft\\windows defender\\platform\\)", source, re.I):
        return True
    return bool(re.match(r"^[a-z]:\\program files(?: \(x86\))?\\(?:"
                         r"eset\\.*\\(?:ekrn|eavp)\.exe|sophos\\.*\\(?:sophoshealth|sophosinterceptx|savservice)\.exe|"
                         r"sysmon\\sysmon(?:64a?|)\.exe)$", source, re.I))


@rule("WLH-026", "Posible inyección de código", "high", ["T1055"],
      "Sysmon 8/10/25: hilos remotos, acceso con escritura y creación de hilos, pila sin módulo o manipulación de imagen.")
def code_injection(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[tuple[str, str, str, str, str], list[Event]] = {}
    for e in events:
        if not _is_sysmon(e) or e.event_id not in (8, 10, 25):
            continue
        source, target = e.get("SourceImage", "Image"), e.get("TargetImage")
        reason, severity = "", "high"
        if e.event_id == 25:
            reason = "Sysmon notificó manipulación de la imagen del proceso"
        elif e.event_id == 8:
            if not source or not target or _routine_thread_source(source, target):
                continue
            reason = "creación de un hilo en otro proceso"
            severity = "high" if _user_path(source) else "medium"
        else:
            # WLH-013 conserva la responsabilidad sobre el acceso a LSASS.
            if _exe(target) == "lsass.exe" or not source or not target or _routine_thread_source(source, target):
                continue
            source_guid, target_guid = e.get("SourceProcessGUID", "SourceProcessGuid"), e.get("TargetProcessGUID", "TargetProcessGuid")
            if source_guid and source_guid.lower() == target_guid.lower():
                continue
            try:
                mask = int(e.get("GrantedAccess"), 16)
            except ValueError:
                mask = 0
            if (mask and mask & 0x2A == 0 and re.fullmatch(r"[a-z]:\\windows\\(?:syswow64\\)?explorer\.exe", source, re.I)):
                # Explorer consulta procesos de aplicaciones normales; UNKNOWN no demuestra inyección.
                continue
            if re.search(r"\bUNKNOWN(?:\(|\+|\b)", e.get("CallTrace"), re.I):
                reason = "acceso desde memoria sin módulo en la pila"
                # Las pilas de JIT también pueden contener UNKNOWN al consultar procesos.
                severity = "low" if mask and mask & 0x2A == 0 else "high"
            else:
                # PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE.
                # 0x0800 solo es PROCESS_SUSPEND_RESUME: no basta para esta señal.
                if mask & 0x2A != 0x2A or not _user_path(source):
                    continue
                reason, severity = "acceso con escritura de memoria y creación de hilos desde un perfil o temporal", "medium"
        groups.setdefault((e.computer.lower(), source, target, reason, severity), []).append(e)
    for (_, source, target, reason, severity), evs in groups.items():
        for burst in _bursts(evs, cfg.window, 1):
            first = burst[0]
            yield Hit(burst, f"{reason.capitalize()} en {first.computer or UNKNOWN}",
                      {"indicador": reason, "proceso_origen": source, "proceso_destino": target,
                       "permisos": sorted({x.get("GrantedAccess") for x in burst if x.get("GrantedAccess")}),
                       "pila": _truncate(first.get("CallTrace")),
                       "tipo": first.get("Type"), "dirección_del_hilo": first.get("StartAddress")}, severity=severity)


_HIJACK_DLLS = {"wwlib.dll", "version.dll", "dbghelp.dll", "cdpsshims.dll", "wlbsctrl.dll"}
_DLL_LOADER_PAIRS = {("winword.exe", "wwlib.dll"), ("svchost.exe", "cdpsshims.dll"),
                     ("svchost.exe", "wlbsctrl.dll")}


@rule("WLH-027", "Carga de DLL sospechosa o sideloading", "medium", ["T1574.001", "T1574.002"],
      "Sysmon 7: DLL explícitamente sin firma fuera de Windows y Program Files, con cargador de sistema o pareja conocida.")
def suspicious_dll(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id != 7 or not _is_sysmon(e) or e.get("Signed").lower() != "false":
            continue
        image, dll = e.get("Image"), e.get("ImageLoaded")
        if not image or not dll or not dll.lower().endswith(".dll"):
            continue
        if _windows_path(dll) or _program_files_path(dll) or _debugger_process(image):
            continue
        name = _exe(dll)
        known_pair = (_exe(image), name) in _DLL_LOADER_PAIRS
        if not _windows_path(image) and not known_pair:
            # version/dbghelp junto a una aplicación portable no prueba un secuestro.
            continue
        label = "DLL de secuestro conocido sin firma" if name in _HIJACK_DLLS else "DLL sin firma fuera de las carpetas de instalación"
        yield Hit([e], f"{_exe(image)} cargó {label} en {e.computer or UNKNOWN}",
                  {"proceso": image, "dll": dll, "firma_de_la_dll": e.get("Signed"), "indicador": label},
                  severity="high" if known_pair else "medium")


