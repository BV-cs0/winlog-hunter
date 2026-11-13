"""Reglas de persistencia."""

from __future__ import annotations

from .base import (Config, Event, Hit, Iterator, UNKNOWN, _INSTALLERS, _PERSISTENCE_KEYS, _REMOTE_EXEC_SERVICE, _SUSPICIOUS_COMMAND, _TASK_ARGS, _TASK_COMMAND, _bursts, _exe, _is_sysmon, _privileged_group, _truncate, defaultdict, html, rule)

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


