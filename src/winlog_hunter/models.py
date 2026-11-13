"""Modelos de datos: eventos normalizados y hallazgos."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from sys import intern

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITIES = tuple(SEVERITY_ORDER)


@dataclass(init=False)
class Event:
    """Evento de Windows normalizado, venga de EVTX, XML o JSON."""

    __slots__ = ("timestamp", "event_id", "computer", "channel", "provider", "data", "_record_id")
    timestamp: datetime
    event_id: int
    computer: str
    channel: str
    provider: str
    data: dict[str, str]

    def __init__(self, timestamp, event_id, computer="", channel="", provider="", data=None, _record_id=0):
        self.timestamp = timestamp
        self.event_id = event_id
        self.computer = intern(computer)
        self.channel = intern(channel)
        self.provider = intern(provider)
        self.data = {intern(k): v for k, v in (data or {}).items()}
        self._record_id = _record_id

    def get(self, *keys: str) -> str:
        """Devuelve el primer campo con un valor útil (ignora vacíos y '-')."""
        for key in keys:
            value = self.data.get(key)
            if value is not None and value.strip() not in ("", "-"):
                return value.strip()
        return ""


@dataclass
class Finding:
    """Resultado de una regla de detección."""

    rule_id: str
    title: str
    severity: str
    mitre: list[str]
    summary: str
    first_seen: datetime
    last_seen: datetime
    computers: list[str]
    evidence: dict[str, Any]
    event_count: int
    veces: int = 1

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre": self.mitre,
            "summary": self.summary,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "computers": self.computers,
            "event_count": self.event_count,
            "veces": self.veces,
            "evidence": self.evidence,
        }
