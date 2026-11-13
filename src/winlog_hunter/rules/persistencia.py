"""Reglas de persistencia."""

from __future__ import annotations

import re
from datetime import timedelta

from ..parsers import parse_timestamp

from .base import (Config, Event, Hit, Iterator, UNKNOWN, _INSTALLERS, _PERSISTENCE_KEYS, _REMOTE_EXEC_SERVICE, _SUSPICIOUS_COMMAND, _TASK_ARGS, _TASK_COMMAND, _bursts, _exe, _is_sysmon, _privileged_group, _truncate, defaultdict, html, rule)
from .base import (_SHELLS, _browser_root, _maintenance_process, _processes, _program_files_path,
                   _user_path, _windows_path)


_EXTRA_PERSISTENCE_KEYS = [
    (re.compile(r"\\appcompatflags\\(?:custom|installedsdb)\\", re.I), "base de compatibilidad de aplicaciones", ["T1546.011"]),
    (re.compile(r"\\winsock2\\parameters\\protocol_catalog9\\", re.I), "catálogo de proveedores Winsock", ["T1574.011"]),
    (re.compile(r"\\control\\networkprovider\\order\\providerorder$", re.I), "orden de proveedores de red", ["T1556.008"]),
    (re.compile(r"\\services\\lanmanserver\\parameters\\nullsessionpipes$", re.I), "pipes accesibles sin autenticación", ["T1021.002"]),
    (re.compile(r"\\control\\print\\monitors\\[^\\]+\\driver$", re.I), "monitor de impresión", ["T1547.010"]),
    (re.compile(r"\\services\\[^\\]+\\parameters\\servicedll$", re.I), "DLL de un servicio", ["T1543.003"]),
    (re.compile(r"\\group policy\\(?:state\\(?:machine|[^\\]+)\\)?scripts\\(?:startup|shutdown|logon|logoff)\\.*\\(?:script|parameters)$", re.I),
     "script de directiva de grupo", ["T1037"]),
    (re.compile(r"\\microsoft\\ieak\\grouppolicy\\pendinggpos\\path\d+$", re.I), "instalación INF pendiente de directiva de grupo", ["T1547.001"]),
]


def _normal_module_path(value: str) -> bool:
    """Rutas de módulos instalados, incluidas las variables de entorno del registro."""
    value = value.strip().strip('"')
    return _windows_path(value) or _program_files_path(value) or bool(re.match(
        r"^(?:%systemroot%|%windir%)\\(?:system32|syswow64|winsxs)\\|^%programfiles(?:\(x86\))?%\\", value, re.I))

@rule(
    "WLH-006",
    "Nuevo servicio instalado",
    "high",
    ["T1543.003"],
    "Evento 7045. Alta si el servicio ejecuta algo sospechoso o es de ejecución remota (PsExec); baja en otro caso.",
)
def service_installed(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id != 7045:
            continue
        name, image = e.get("ServiceName"), e.get("ImagePath")
        indicators = []
        mitre = ["T1543.003"]
        if _REMOTE_EXEC_SERVICE.match(name):
            indicators.append("servicio típico de ejecución remota (PsExec o similar)")
            mitre += ["T1569.002", "T1021.002"]
        match = _SUSPICIOUS_COMMAND.search(image)
        if match:
            indicators.append(f"comando sospechoso: '{match.group(0).strip()}'")
        yield Hit(
            [e],
            f"Servicio '{name or UNKNOWN}' instalado en {e.computer or UNKNOWN}",
            {
                "servicio": name,
                "ruta": _truncate(image),
                "cuenta": e.get("AccountName"),
                "tipo_de_inicio": e.get("StartType"),
                "indicadores": indicators,
            },
            severity="high" if indicators else "low",
            mitre=mitre,
        )


@rule(
    "WLH-007",
    "Tarea programada creada",
    "high",
    ["T1053.005"],
    "Evento 4698. Alta si la tarea lanza PowerShell, scripts o rutas sospechosas; baja en otro caso.",
)
def scheduled_task(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id != 4698:
            continue
        content = html.unescape(e.get("TaskContent"))
        commands = [c.strip() for c in _TASK_COMMAND.findall(content)]
        arguments = [a.strip() for a in _TASK_ARGS.findall(content)]
        action = " ".join(commands + arguments) or content
        match = _SUSPICIOUS_COMMAND.search(action)
        yield Hit(
            [e],
            f"Tarea '{e.get('TaskName') or UNKNOWN}' creada en {e.computer or UNKNOWN} por {e.get('SubjectUserName') or UNKNOWN}",
            {
                "tarea": e.get("TaskName"),
                "usuario": e.get("SubjectUserName"),
                "acción": _truncate(action),
                "indicadores": [f"comando sospechoso: '{match.group(0).strip()}'"] if match else [],
            },
            severity="high" if match else "low",
        )


@rule(
    "WLH-008",
    "Cuenta de usuario creada",
    "medium",
    ["T1136"],
    "Evento 4720: se creó una cuenta nueva. Revisa si estaba planificada.",
)
def user_created(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id != 4720:
            continue
        target, subject = e.get("TargetUserName", "SamAccountName"), e.get("SubjectUserName")
        yield Hit(
            [e],
            f"Cuenta '{target or UNKNOWN}' creada por '{subject or UNKNOWN}' en {e.computer or UNKNOWN}",
            {"cuenta": target, "creada_por": subject, "dominio": e.get("TargetDomainName")},
        )


@rule(
    "WLH-009",
    "Miembro añadido a grupo privilegiado",
    "high",
    ["T1098"],
    "Eventos 4728/4732/4756 sobre grupos como Administradores o Admins. del dominio (detectados por SID).",
)
def privileged_group_add(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id not in (4728, 4732, 4756):
            continue
        privileged, critical = _privileged_group(e)
        if not privileged:
            continue
        group = e.get("TargetUserName") or e.get("TargetSid")
        member = e.get("MemberName", "MemberSid")
        yield Hit(
            [e],
            f"'{member or UNKNOWN}' añadido a '{group}' por '{e.get('SubjectUserName') or UNKNOWN}'",
            {
                "grupo": group,
                "sid_grupo": e.get("TargetSid"),
                "miembro": e.get("MemberName"),
                "sid_miembro": e.get("MemberSid"),
                "añadido_por": e.get("SubjectUserName"),
            },
            severity="critical" if critical else None,
        )


@rule(
    "WLH-019",
    "Persistencia en el registro",
    "high",
    ["T1547.001"],
    "Sysmon 13: se escribe en claves de arranque (Run, Winlogon, IFEO, AppInit, LSA, COM...) desde un proceso que no es un instalador.",
)
def registry_persistence(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id not in (12, 13, 14) or not _is_sysmon(e):
            continue
        key, image = e.get("TargetObject", "NewName"), e.get("Image")
        if not key or _INSTALLERS.match(image):
            continue
        if re.search(r"\\session manager\\bootexecute$", key, re.I) and e.get("Details").strip().lower() == "autocheck autochk *":
            continue
        for pattern, label, mitre in _PERSISTENCE_KEYS:
            if not pattern.search(key):
                continue
            if "RID" in label and _exe(image) == "lsass.exe":
                break  # LSASS actualiza ese valor en cada inicio de sesión
            details = e.get("Details")
            suspicious = _SUSPICIOUS_COMMAND.search(details) or _SUSPICIOUS_COMMAND.search(image)
            yield Hit(
                [e],
                f"{_exe(image) or UNKNOWN} modificó {label} en {e.computer or UNKNOWN}",
                {
                    "clave": key,
                    "valor": _truncate(details),
                    "proceso": image,
                    "usuario": e.get("User"),
                },
                mitre=mitre,
                severity="medium" if "Run" in label and not suspicious else None,
            )
            break
        else:
            # Las claves nuevas tienen sus propios filtros; no cambian las selecciones anteriores.
            if e.event_id != 13 or not e.get("Details") or _maintenance_process(image):
                continue
            if _windows_path(image) and _exe(image) in {"svchost.exe", "spoolsv.exe", "services.exe"}:
                continue
            for pattern, label, mitre in _EXTRA_PERSISTENCE_KEYS:
                if not pattern.search(key):
                    continue
                value = e.get("Details")
                if label in {"DLL de un servicio", "monitor de impresión"} and _normal_module_path(value):
                    break
                if label == "orden de proveedores de red" and set(value.lower().replace(" ", "").split(",")) <= {"rdpnp", "lanmanworkstation", "webclient"}:
                    break
                # Registros de compatibilidad, catálogos de red y GPO también son administración normal.
                severity = "medium" if _user_path(value.strip('"')) and label in {"DLL de un servicio", "monitor de impresión", "script de directiva de grupo"} else "low"
                yield Hit([e], f"{_exe(image) or UNKNOWN} modificó {label} en {e.computer or UNKNOWN}",
                          {"clave": key, "valor": _truncate(value), "proceso": image, "indicador": label},
                          mitre=mitre, severity=severity)
                break
    for p in _processes(events):
        if (_exe(p.parent) != "smss.exe" or not _windows_path(p.parent) or not p.image or
            _windows_path(p.image) or _exe(p.image) in _SHELLS):
            continue
        yield Hit([p.event], f"smss lanzó un proceso fuera de las carpetas de sistema en {p.event.computer or UNKNOWN}",
                  {"proceso": p.image, "proceso_padre": p.parent, "línea_de_comandos": _truncate(p.command_line)},
                  mitre=["T1547.001"])


@rule(
    "WLH-020",
    "Persistencia con WMI",
    "high",
    ["T1546.003"],
    "Sysmon 19/20/21: se crea un filtro, consumidor o enlace de eventos WMI que ejecuta algo de forma permanente.",
)
def wmi_persistence(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id in (19, 20, 21) and _is_sysmon(e) and e.get("Operation").lower() in ("", "created", "modified"):
            groups[e.computer.lower()].append(e)
    for evs in groups.values():
        for burst in _bursts(evs, cfg.window, 1):
            consumer = next((x for x in burst if x.event_id == 20), None)
            filt = next((x for x in burst if x.event_id == 19), None)
            name = (consumer or filt or burst[0]).get("Name", "Consumer").strip('"')
            yield Hit(
                burst,
                f"Suscripción WMI '{name or UNKNOWN}' creada en {burst[0].computer or UNKNOWN}",
                {
                    "nombre": name,
                    "usuario": burst[0].get("User"),
                    "consulta": _truncate(filt.get("Query").strip('"')) if filt else "",
                    "acción": _truncate(consumer.get("Destination").strip('"')) if consumer else "",
                    "tipo": consumer.get("Type") if consumer else "",
                },
            )


_STARTUP_FILE = re.compile(r"\\start menu\\programs\\startup\\[^\\]+\.(?:lnk|exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|wsf|url)$", re.I)
_ROOT_SERVICE_EXE = re.compile(r"^[a-z]:\\(?:program\.exe|program files(?: \(x86\))?\\[^\\]+\.exe)$", re.I)
_CODE_FILE = re.compile(r"\.(?:exe|dll|sys|ps1|bat|cmd|vbs|vbe|js|jse|wsf)$", re.I)


def _routine_file_writer(image: str) -> bool:
    """Copias, descargas y compilaciones legítimas suelen conservar fechas de ficheros."""
    if _maintenance_process(image) or _browser_root(image):
        return True
    if re.fullmatch(r"[a-z]:\\windows\\(?:syswow64\\)?explorer\.exe", image, re.I):
        return True
    return (_windows_path(image) or _program_files_path(image)) and _exe(image) in {
        "robocopy.exe", "xcopy.exe", "tar.exe", "7z.exe", "7zfm.exe", "winrar.exe", "chrome.exe", "msedge.exe", "firefox.exe",
        "devenv.exe", "msbuild.exe", "dotnet.exe", "nuget.exe", "code.exe",
    }


@rule("WLH-030", "Ficheros sospechosos", "medium", ["T1547.001", "T1003", "T1574.001", "T1574.009", "T1070.006"],
      "Sysmon 11/2: inicio, volcados de LSASS, memssp, rutas ambiguas de servicio, spooler y cambios de fecha hacia el pasado.")
def suspicious_files(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id not in (2, 11) or not _is_sysmon(e):
            continue
        image, target = e.get("Image"), e.get("TargetFilename")
        name, filename = _exe(image), _exe(target)
        if not target or _maintenance_process(image):
            continue
        reason, technique, severity = "", "T1547.001", "medium"
        if e.event_id == 11:
            if _STARTUP_FILE.search(target):
                reason = "fichero ejecutable o acceso directo escrito en Inicio"
            elif filename == "mimilsa.log":
                reason, technique, severity = "registro por defecto de memssp", "T1003.001", "high"
            elif target.lower().endswith(".dmp") and name not in {"werfault.exe", "werfaultsecure.exe", "wermgr.exe"} and (
                name in {"lsass.exe", "rdrleakdiag.exe"} or re.fullmatch(r"lsass(?:[._-]\d+)*\.dmp", filename)):
                # Los .dmp de navegadores, Office y Visual Studio no prueban robo de credenciales.
                reason, technique, severity = "posible volcado de memoria de LSASS", "T1003.001", "high"
            elif _ROOT_SERVICE_EXE.fullmatch(target):
                reason, technique = "ejecutable en una ruta candidata a secuestro de servicio sin comillas", "T1574.009"
            elif re.match(r"^[a-z]:\\windows\\system32\\spool\\drivers\\", target, re.I) and target.lower().endswith((".dll", ".exe", ".sys")):
                if _windows_path(image) and name in {"spoolsv.exe", "printisolationhost.exe", "drvinst.exe", "pnputil.exe", "printfilterpipelinesvc.exe", "rundll32.exe"}:
                    continue
                reason, technique = "binario escrito en el directorio de controladores de impresión", "T1574.001"
        elif _CODE_FILE.search(target) and _user_path(target) and not _routine_file_writer(image):
            try:
                previous = parse_timestamp(e.get("PreviousCreationUtcTime"))
                current = parse_timestamp(e.get("CreationUtcTime"))
            except (ValueError, TypeError):
                continue
            if previous - current >= timedelta(days=1):
                reason, technique = "fecha de creación de código retrasada al menos un día", "T1070.006"
        if reason:
            yield Hit([e], f"{reason.capitalize()} en {e.computer or UNKNOWN}",
                      {"indicador": reason, "fichero": target, "proceso": image,
                       "fecha_anterior": e.get("PreviousCreationUtcTime"), "fecha_nueva": e.get("CreationUtcTime")},
                      severity=severity, mitre=[technique])


