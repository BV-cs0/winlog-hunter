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

# Banderas de arranque: dicen cómo se lanza PowerShell, no qué hace. Instaladores y herramientas
# legítimas (VS Code, Al Día, gestores de versiones) las usan a diario.
_BANDERAS_DE_ARRANQUE = {"ventana oculta", "sin perfil", "bypass de política"}
# El primer -Command o -File decide: lo que va detrás de -Command es texto del comando,
# aunque contenga «-File» (Get-ChildItem -File).
_SCRIPT = re.compile(r'(?:^|\s)[-/](?:(c(?:ommand)?)|f(?:ile)?)\s+(?:"([^"]+)"|(\S+))', re.I)


def _solo_banderas_rutinarias(command_line: str, indicators: list[str]) -> bool:
    """Solo banderas de arranque, con un comando escrito en la línea o un script instalado.

    Un script en una carpeta que puede escribir el usuario (Temp, Descargas...) sigue siendo media.
    """
    if not set(indicators) <= _BANDERAS_DE_ARRANQUE:
        return False
    script = _SCRIPT.search(command_line)
    if not script or script.group(1):
        return True
    ruta = script.group(2) or script.group(3)
    return _program_files_path(ruta) or _windows_path(ruta, ("system32", "syswow64"))


_LOLBINS_POR_NOMBRE = {}
for _nombre, _patron, _mitre, _tecnica in _LOLBINS + _MORE_LOLBINS:
    _LOLBINS_POR_NOMBRE.setdefault(_nombre, []).append((_patron, _mitre, _tecnica))

@rule(
    "WLH-010",
    "PowerShell sospechoso",
    "high",
    ["T1059.001"],
    "PowerShell con comando codificado, descarga + IEX o evasión de AMSI (alta); varias banderas de ocultación (media; "
    "baja si solo son banderas de arranque con un comando en la línea o un script de Program Files).",
    eventos={4688, 1},
    agrupar_por=('proceso_padre', 'línea_de_comandos', 'comando_decodificado', 'usuario', 'indicadores'),
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
        severity = "high" if strong else "low" if _solo_banderas_rutinarias(p.command_line, indicators) else "medium"
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
            severity=severity,
        )


@rule(
    "WLH-011",
    "Uso malicioso de binario del sistema (LOLBin)",
    "high",
    ["T1218"],
    "Binarios legítimos con argumentos de ejecución indirecta, carga de scripts o descarga remota.",
    eventos={4688, 1, 1042, 1040},
    agrupar_por=('binario', 'técnica', 'proceso_padre', 'línea_de_comandos', 'usuario', 'url', 'indicador'),
)
def lolbins(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id in (1040, 1042) and e.provider.lower() == "msiinstaller" and e.channel.lower() in {"application", ""}:
            text = " ".join(e.data.values())
            urls = re.findall(r'https?://[^\s"<>]+', text, re.I)
            if urls:
                yield Hit([e], f"Windows Installer procesó un paquete desde URL en {e.computer or UNKNOWN}",
                          {"url": _truncate(urls[0]), "indicador": "paquete de instalación remoto"},
                          severity="low", mitre=["T1218.007"])
    for p in _processes(events):
        exe = _exe(p.image)
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
        for pattern, mitre, technique in _LOLBINS_POR_NOMBRE.get(exe, ()):
            if pattern.search(p.command_line):
                name = exe
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
      "Servidores o servicios abren intérpretes, activación DCOM inusual y auditoría SQL de xp_cmdshell.", eventos={4688, 1, 15457, 33205},
    agrupar_por=('indicador', 'proceso_padre', 'proceso_hijo', 'línea_de_comandos', 'usuario', 'comando_del_padre', 'sentencia'),
)
def server_shell(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if not e.provider.lower().startswith("mssql"):
            continue
        enabled = e.event_id == 15457 and e.get("Data0", "OptionName").lower() == "xp_cmdshell" and e.get("Data2", "NewValue") == "1" and e.get("Data1", "OldValue") != "1"
        statement = e.get("statement", "Statement", "Data0")
        execution = e.event_id == 33205 and e.get("succeeded", "Succeeded").lower() not in {"false", "0"} and bool(re.search(r"\bexec(?:ute)?\s+(?:[\w\[\]]+\.){0,2}\[?xp_cmdshell\b", statement, re.I))
        if enabled or execution:
            yield Hit([e], f"SQL Server {'habilitó' if enabled else 'ejecutó'} xp_cmdshell en {e.computer or UNKNOWN}",
                      {"indicador": "xp_cmdshell habilitado" if enabled else "ejecución de xp_cmdshell", "sentencia": _truncate(statement)},
                      severity="medium", mitre=["T1505.001", "T1059.003"])
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
    eventos={4688, 1},
    agrupar_por=('proceso_padre', 'proceso_hijo', 'línea_de_comandos', 'usuario'),
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
    "PowerShell 4104, 4103 y 800: indicadores de volcado, AMSI, inyección, descarga dinámica y ofuscación combinada.",
    eventos={4104, 800, 4103},
)
def malicious_script_block(events: list[Event], cfg: Config) -> Iterator[Hit]:
    seen: set[tuple[str, int, str]] = set()
    for e in events:
        if e.event_id == 4104:
            text = e.get("ScriptBlockText")
        elif e.event_id in (4103, 800) and ("powershell" in (e.channel + e.provider).lower()):
            text = "\n".join(e.get(k) for k in ("Payload", "ContextInfo", "HostApplication", "Data0", "Data1", "Data2", "Message"))
        else:
            continue
        normalized = text.replace("`", "")
        for _ in range(6):
            folded = re.sub(r"(['\"])([a-z0-9_.-]*)\1\s*\+\s*(['\"])([a-z0-9_.-]*)\3", lambda m: "'" + m[2] + m[4] + "'", normalized, flags=re.I)
            if folded == normalized:
                break
            normalized = folded
        found = [(name, mitre) for name, regex, mitre in _SCRIPT_BLOCK_INDICATORS if text and regex.search(normalized)]
        dynamic = bool(re.search(r"\b(?:iex|invoke-expression)\b", normalized, re.I) and re.search(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b", normalized, re.I))
        download = bool(re.search(r"net\.webclient", normalized, re.I) and re.search(r"downloadfile", normalized, re.I))
        obfuscation = (len(re.findall(r"\[char\]", normalized, re.I)) >= 4 or "-join" in normalized.lower()) and (dynamic or download)
        temp_exec = bool(re.search(r"invoke-item[\s\S]{0,160}(?:%temp%|\$env:temp|\\temp\\)[\s\S]{0,160}\.exe\b", normalized, re.I))
        if dynamic:
            found.append(("descarga con ejecución dinámica", "T1059.001"))
        if download:
            found.append(("WebClient con descarga a fichero", "T1105"))
        if obfuscation:
            found.append(("ofuscación combinada con descarga o ejecución", "T1027"))
        if temp_exec:
            found.append(("ejecución de un fichero temporal", "T1059.001"))
        block = (e.computer.lower(), e.event_id, e.get("ScriptBlockId") or text)
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
            severity="critical" if any(m.startswith("T1003") for _, m in found) else
                     "high" if dynamic or obfuscation or any(m not in {"T1105", "T1059.001"} for _, m in found) or any(regex.search(normalized) for _, regex, _ in _SCRIPT_BLOCK_INDICATORS) else "low",
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
      "Sysmon 8/10/25: hilos remotos, acceso con escritura y creación de hilos, pila sin módulo o manipulación de imagen.", eventos={8, 25, 10})
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
      "Sysmon 7: DLL explícitamente sin firma fuera de Windows y Program Files, con cargador de sistema o pareja conocida.", eventos={7},
    agrupar_por=('proceso', 'dll', 'firma_de_la_dll', 'indicador'),
)
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


