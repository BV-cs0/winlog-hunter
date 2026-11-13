"""Reglas de evasion."""

from __future__ import annotations

from .base import (Config, Event, Hit, Iterator, UNKNOWN, rule)

@rule(
    "WLH-005",
    "Registro de eventos borrado",
    "critical",
    ["T1685.005"],
    "Se vació el registro de seguridad (1102) u otro registro (104): típico para borrar huellas.",
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


