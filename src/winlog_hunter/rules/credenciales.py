"""Reglas de credenciales."""

from __future__ import annotations

from .base import (AccountKey, Any, Config, Event, Hit, Iterator, UNKNOWN, _DUMP_COMMANDS, _DUMP_TOOLS, _LSASS_ALLOWED, _PROCESS_VM_READ, _REPLICATION_GUIDS, _account_key, _bursts, _duration, _exe, _failed_logons, _failure_reasons, _is_sysmon, _is_system_account, _logon_label, _logon_types, _processes, _source, _truncate, _user, bisect_left, bisect_right, defaultdict, rule)

@rule(
    "WLH-001",
    "Fuerza bruta de credenciales",
    "high",
    ["T1110.001"],
    "Muchos inicios de sesión fallidos (4625) contra la misma cuenta y desde el mismo origen en poco tiempo.",
)
def brute_force(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for (_, _, _, source), evs in _failed_logons(events).items():
        for burst in _bursts(evs, cfg.window, cfg.brute_force_threshold):
            user = _user(burst[0])
            yield Hit(
                burst,
                f"{len(burst)} inicios de sesión fallidos para '{user}' desde {source} en {_duration(burst)}",
                {
                    "usuario": user,
                    "origen": source,
                    "intentos": len(burst),
                    "tipos_de_logon": _logon_types(burst),
                    "motivos": _failure_reasons(burst),
                },
            )


@rule(
    "WLH-002",
    "Password spraying",
    "high",
    ["T1110.003"],
    "Un mismo origen falla el inicio de sesión contra muchas cuentas distintas en poco tiempo.",
)
def password_spray(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id == 4625 and _user(e) and _source(e) != UNKNOWN:
            groups[_source(e)].append(e)
    for source, evs in groups.items():
        for burst in _bursts(evs, cfg.window, cfg.spray_min_accounts, distinct=lambda e: _user(e).lower()):
            accounts = sorted({_user(e).lower(): _user(e) for e in burst}.values(), key=str.lower)
            yield Hit(
                burst,
                f"{source} probó {len(accounts)} cuentas distintas en {_duration(burst)}",
                {
                    "origen": source,
                    "cuentas_distintas": len(accounts),
                    "cuentas": accounts[:25],
                    "intentos": len(burst),
                    "motivos": _failure_reasons(burst),
                },
            )


@rule(
    "WLH-003",
    "Inicio de sesión correcto tras fuerza bruta",
    "critical",
    ["T1110", "T1078"],
    "Un 4624 llega justo después de una ráfaga de 4625 para la misma cuenta y origen: probable credencial comprometida.",
)
def success_after_failures(events: list[Event], cfg: Config) -> Iterator[Hit]:
    failures = _failed_logons(events)
    times = {key: [e.timestamp for e in evs] for key, evs in failures.items()}
    last_alert: dict[AccountKey, Any] = {}
    for e in events:
        if e.event_id != 4624 or not _user(e):
            continue
        key = _account_key(e)
        if key not in failures:
            continue
        lo = bisect_left(times[key], e.timestamp - cfg.success_lookback)
        hi = bisect_right(times[key], e.timestamp)
        prior = failures[key][lo:hi]
        if len(prior) < cfg.brute_force_threshold:
            continue
        if key in last_alert and e.timestamp - last_alert[key] <= cfg.success_lookback:
            continue
        last_alert[key] = e.timestamp
        yield Hit(
            prior + [e],
            f"'{_user(e)}' inició sesión con éxito desde {key[3]} tras {len(prior)} intentos fallidos",
            {
                "usuario": _user(e),
                "dominio": e.get("TargetDomainName"),
                "origen": key[3],
                "intentos_fallidos_previos": len(prior),
                "tipo_de_logon": _logon_label(e.get("LogonType")),
                "id_de_logon": e.get("TargetLogonId"),
            },
        )


@rule(
    "WLH-013",
    "Acceso a la memoria de LSASS",
    "critical",
    ["T1003.001"],
    "Sysmon 10: un proceso abre lsass.exe con permiso de lectura de memoria. Así roban contraseñas Mimikatz, procdump o comsvcs.",
)
def lsass_access(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        if e.event_id != 10 or not _is_sysmon(e) or _exe(e.get("TargetImage")) != "lsass.exe":
            continue
        source, mask, trace = e.get("SourceImage"), e.get("GrantedAccess").lower(), e.get("CallTrace")
        try:
            can_read = bool(int(mask, 16) & _PROCESS_VM_READ)
        except ValueError:
            can_read = False
        tool = _DUMP_TOOLS.search(f"{source} {trace}")
        trusted = _exe(source) in _LSASS_ALLOWED and source.lower().startswith(("c:\\windows\\", "c:\\program"))
        if not can_read or (trusted and not tool):
            continue
        indicators = []
        if tool:
            indicators.append(f"herramienta de volcado: '{tool.group(0)}'")
        if "unknown(" in trace.lower():
            indicators.append("código sin módulo en la pila (inyectado o reflectivo)")
        yield Hit(
            [e],
            f"{_exe(source) or UNKNOWN} accedió a la memoria de lsass.exe en {e.computer or UNKNOWN}",
            {
                "proceso_origen": source,
                "permisos": mask,
                "usuario": e.get("SourceUser"),
                "indicadores": indicators,
            },
            severity="critical" if indicators else "high",
        )


@rule(
    "WLH-014",
    "Comando de volcado de credenciales",
    "critical",
    ["T1003"],
    "Sysmon 1/4688: comsvcs MiniDump, procdump contra LSASS, ntdsutil IFM, reg save de SAM o comandos de Mimikatz.",
)
def credential_dump_command(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        for name, pattern, mitre in _DUMP_COMMANDS:
            if pattern.search(p.command_line):
                yield Hit(
                    [p.event],
                    f"{name} en {p.event.computer or UNKNOWN}",
                    {
                        "técnica": name,
                        "usuario": p.user,
                        "proceso": p.image,
                        "proceso_padre": p.parent,
                        "línea_de_comandos": _truncate(p.command_line),
                    },
                    mitre=[mitre],
                )
                break


@rule(
    "WLH-015",
    "DCSync",
    "critical",
    ["T1003.006"],
    "Evento 4662 con derechos de replicación de AD pedidos por una cuenta que no es un controlador de dominio.",
)
def dcsync(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id != 4662:
            continue
        props = e.get("Properties").lower()
        user = e.get("SubjectUserName")
        if not user or _is_system_account(user) or not any(g in props for g in _REPLICATION_GUIDS):
            continue
        groups[(user.lower(), e.computer.lower())].append(e)
    for evs in groups.values():
        for burst in _bursts(evs, cfg.window, 1):
            props = " ".join(x.get("Properties").lower() for x in burst)
            yield Hit(
                burst,
                f"'{burst[0].get('SubjectUserName')}' pidió replicar el directorio en {burst[0].computer or UNKNOWN}",
                {
                    "usuario": burst[0].get("SubjectUserName"),
                    "dominio": burst[0].get("SubjectDomainName"),
                    "derechos": sorted(n for g, n in _REPLICATION_GUIDS.items() if g in props),
                },
            )


@rule(
    "WLH-016",
    "Kerberoasting",
    "high",
    ["T1558.003"],
    "Eventos 4769 pidiendo tickets de servicio con cifrado RC4 (0x17) para cuentas de usuario: típico de Rubeus o GetUserSPNs.",
)
def kerberoasting(events: list[Event], cfg: Config) -> Iterator[Hit]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id != 4769 or e.get("TicketEncryptionType").lower() != "0x17":
            continue
        if e.get("Status").lower() not in ("", "0x0"):
            continue
        service, user = e.get("ServiceName"), e.get("TargetUserName").split("@", 1)[0]
        if not service or service.endswith("$") or service.lower().startswith("krbtgt") or user.endswith("$"):
            continue
        groups[user.lower()].append(e)
    for evs in groups.values():
        for burst in _bursts(evs, cfg.window, 1):
            services = sorted({e.get("ServiceName") for e in burst}, key=str.lower)
            user = burst[0].get("TargetUserName").split("@", 1)[0]
            yield Hit(
                burst,
                f"'{user}' pidió {len(burst)} ticket(s) RC4 para {len(services)} servicio(s)",
                {
                    "usuario": user,
                    "origen": burst[0].get("IpAddress").replace("::ffff:", ""),
                    "servicios": services[:25],
                    "cifrado": "RC4 (0x17)",
                },
                severity="high" if len(services) >= 2 else "medium",
            )


