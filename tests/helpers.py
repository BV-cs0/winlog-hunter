from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from winlog_hunter.models import Event  # noqa: E402

BASE = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)
SAMPLE = ROOT / "samples" / "escenario_ataque.jsonl"


def ev(event_id: int, seconds: float = 0, computer: str = "HOST", channel: str = "Security",
       provider: str = "", **data: str) -> Event:
    return Event(
        timestamp=BASE + timedelta(seconds=seconds),
        event_id=event_id,
        computer=computer,
        channel=channel,
        provider=provider,
        data={k: str(v) for k, v in data.items()},
    )


def sysmon(seconds: float, image: str, command: str, parent: str = r"C:\Windows\explorer.exe",
           computer: str = "WS01") -> Event:
    return ev(1, seconds, computer, "Microsoft-Windows-Sysmon/Operational",
              Image=image, CommandLine=command, ParentImage=parent, User="CORP\\user")
