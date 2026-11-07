"""Análisis del propio equipo y tarea programada diaria (solo Windows).

``analyze_this_computer`` exporta los registros de las últimas horas con ``wevtutil``,
los analiza y guarda el informe. ``schedule`` crea una tarea programada que ejecuta
``python -m winlog_hunter equipo`` cada día como SYSTEM, así que sigue funcionando
aunque se actualice el paquete con pip.
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable
from xml.sax.saxutils import escape

from .models import SEVERITY_ORDER
from .parsers import load_events
from .report import RENDERERS, SEVERITY_LABEL, Stats
from .rules import run_rules

TASK_NAME = "winlog-hunter diario"
LOGS = (
    "Security",
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
)
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class LocalError(Exception):
    """Error que se muestra al usuario tal cual."""


def require_windows() -> None:
    if os.name != "nt":
        raise LocalError("este comando solo funciona en Windows (usa 'analyze' con ficheros exportados)")


def is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def documents_dir() -> Path:
    """Carpeta Documentos real del usuario (respeta la redirección a OneDrive)."""
    try:
        import ctypes
        from ctypes import wintypes

        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf) == 0:  # type: ignore[attr-defined]
            return Path(buf.value)
    except Exception:
        pass
    return Path.home() / "Documents"


def default_output() -> Path:
    return documents_dir() / "winlog-hunter"


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", creationflags=_NO_WINDOW)


# --------------------------------------------------------------------------- #
# Exportación
# --------------------------------------------------------------------------- #


@dataclass
class Export:
    files: list[Path] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)


def export_logs(hours: int, folder: Path) -> Export:
    """Exporta con wevtutil los registros de las últimas ``hours`` horas."""
    result = Export()
    listed = _run(["wevtutil", "el"])
    available = {line.strip().lower() for line in listed.stdout.splitlines()}
    query = f"*[System[TimeCreated[timediff(@SystemTime) <= {hours * 3_600_000}]]]"
    for log in LOGS:
        if log.lower() not in available:
            result.messages.append(f"Omitido {log}: no existe en este equipo")
            continue
        target = folder / (log.replace("/", "_") + ".evtx")
        proc = _run(["wevtutil", "epl", log, str(target), f"/q:{query}"])
        if proc.returncode != 0:
            reason = " ".join((proc.stderr or proc.stdout).split())
            if log == "Security":
                reason += " (Security necesita ejecutarse como administrador)"
            result.messages.append(f"Omitido {log}: {reason}")
            continue
        result.files.append(target)
        result.messages.append(f"Exportado {log}")
    return result


# --------------------------------------------------------------------------- #
# Análisis del propio equipo
# --------------------------------------------------------------------------- #


@dataclass
class LocalResult:
    html: Path
    json: Path
    events: int
    counts: dict[str, int]
    alerts: list[str]
    exit_code: int


def analyze_this_computer(
    hours: int = 24,
    output: Path | None = None,
    keep_days: int = 30,
    notify_from: str | None = "critical",
    log: Callable[[str], None] = print,
    exporter: Callable[[int, Path], Export] = export_logs,
    notifier: Callable[[str], None] | None = None,
) -> LocalResult:
    output = output or default_output()
    output.mkdir(parents=True, exist_ok=True)
    journal = output / "ejecuciones.log"

    def say(message: str) -> None:
        log(message)
        with journal.open("a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {message}\n")

    say(f"Inicio: análisis de las últimas {hours} h")
    stamp = f"{datetime.now():%Y-%m-%d_%H%M}"
    tmp = Path(tempfile.mkdtemp(prefix="winlog-hunter-"))
    try:
        exported = exporter(hours, tmp)
        for message in exported.messages:
            say(f"  {message}")
        if not exported.files:
            raise LocalError("no se pudo exportar ningún registro")

        loaded = load_events(exported.files)
        findings = run_rules(loaded.events)
        stats = Stats(
            events=len(loaded.events),
            files=loaded.files,
            first_event=loaded.events[0].timestamp if loaded.events else None,
            last_event=loaded.events[-1].timestamp if loaded.events else None,
            warnings=loaded.warnings,
        )
        html = output / f"informe_{stamp}.html"
        report_json = output / f"informe_{stamp}.json"
        html.write_text(RENDERERS["html"](findings, stats), encoding="utf-8")
        report_json.write_text(RENDERERS["json"](findings, stats), encoding="utf-8")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "high", "medium", "low")}
    say(
        f"  {stats.events} eventos · {len(findings)} hallazgos (crítica {counts['critical']} · "
        f"alta {counts['high']} · media {counts['medium']} · baja {counts['low']})"
    )
    say(f"  Informe: {html}")

    limit = datetime.now() - timedelta(days=keep_days)
    for old in output.glob("informe_*"):
        if datetime.fromtimestamp(old.stat().st_mtime) < limit:
            old.unlink(missing_ok=True)

    alerts: list[str] = []
    if notify_from:
        minimum = SEVERITY_ORDER[notify_from]
        serious = [f for f in findings if f.rank >= minimum]
        alerts = [f"[{SEVERITY_LABEL[f.severity]}] {f.summary}" for f in serious]
        if serious:
            text = (
                f"winlog-hunter: {len(serious)} hallazgo(s) importantes en {os.environ.get('COMPUTERNAME', 'este equipo')}"
                "\n\n" + "\n".join(alerts[:5]) + f"\n\nInforme: {html}"
            )
            (notifier or notify)(text)
            say(f"  Aviso mostrado en pantalla ({len(serious)} hallazgo(s))")

    return LocalResult(html, report_json, stats.events, counts, alerts, 1 if counts["critical"] else 0)


def notify(text: str) -> None:
    """Muestra un aviso en el escritorio. msg.exe llega al usuario aunque se ejecute como SYSTEM."""
    _run(["msg.exe", "*", "/TIME:43200", text])


# --------------------------------------------------------------------------- #
# Tarea programada
# --------------------------------------------------------------------------- #


def task_command(hours: int, output: Path, notify_from: str, python: str | None = None) -> tuple[str, str]:
    """Programa y argumentos que ejecuta la tarea programada."""
    python = python or sys.executable
    pythonw = Path(python).with_name("pythonw.exe")
    exe = str(pythonw if pythonw.exists() else python)
    args = f'-m winlog_hunter equipo --horas {hours} --salida "{output}" --avisar-desde {notify_from} --sin-abrir'
    return exe, args


def task_xml(hour: str, hours: int, output: Path, notify_from: str, python: str | None = None) -> str:
    exe, args = task_command(hours, output, notify_from, python)
    start = f"{datetime.now():%Y-%m-%d}T{hour}:00"
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Analiza los logs de Windows con winlog-hunter y guarda un informe diario.</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(exe)}</Command>
      <Arguments>{escape(args)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def _require_admin(action: str) -> None:
    if not is_admin():
        raise LocalError(f"para {action} abre PowerShell como administrador")


def schedule(hour: str, hours: int, output: Path, notify_from: str) -> None:
    require_windows()
    _require_admin("programar la tarea")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        xml_path = Path(tmp) / "tarea.xml"
        xml_path.write_text(task_xml(hour, hours, output, notify_from), encoding="utf-16")
        proc = _run(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(xml_path), "/F"])
    if proc.returncode != 0:
        raise LocalError("no se pudo crear la tarea: " + " ".join((proc.stderr or proc.stdout).split()))


def unschedule() -> bool:
    require_windows()
    _require_admin("quitar la tarea")
    proc = _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    return proc.returncode == 0


def run_now() -> None:
    require_windows()
    _require_admin("lanzar la tarea")
    proc = _run(["schtasks", "/Run", "/TN", TASK_NAME])
    if proc.returncode != 0:
        raise LocalError("la tarea no existe; créala con: winlog-hunter programar")


def task_status() -> str | None:
    """Estado de la tarea ('Listo', 'En ejecución'...) o None si no existe o no se puede ver."""
    if os.name != "nt":
        return None
    proc = _run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "CSV", "/NH"])
    lines = proc.stdout.strip().splitlines()
    if proc.returncode != 0 or not lines:
        return None
    row = next(csv.reader([lines[0]]), [])
    return row[2] if len(row) > 2 else lines[0]
