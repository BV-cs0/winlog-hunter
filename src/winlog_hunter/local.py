"""Análisis del propio equipo y tarea programada diaria (solo Windows).

``analyze_this_computer`` exporta los registros de las últimas horas con ``wevtutil``,
los analiza y guarda el informe. ``schedule`` crea una tarea programada que ejecuta
``python -m winlog_hunter equipo`` cada día como SYSTEM, así que sigue funcionando
aunque se actualice el paquete con pip.
"""

from __future__ import annotations

import csv
import json
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


# --------------------------------------------------------------------------- #
# Sysmon
# --------------------------------------------------------------------------- #

SYSMON_URL = "https://download.sysinternals.com/files/Sysmon.zip"
SYSMON_CONFIG = Path(__file__).with_name("data") / "sysmon.xml"
SYSMON_INSTALL_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "winlog-hunter"
_MICROSOFT_SIGNERS = ("O=Microsoft Corporation",)


def sysmon_service() -> str | None:
    """Nombre del servicio de Sysmon instalado ('Sysmon64' o 'Sysmon'), o None."""
    for name in ("Sysmon64", "Sysmon"):
        if _run(["sc.exe", "query", name]).returncode == 0:
            return name
    return None


def _verify_microsoft_signature(exe: Path) -> None:
    script = (
        f"$s = Get-AuthenticodeSignature -LiteralPath '{exe}'; "
        "Write-Output $s.Status; Write-Output $s.SignerCertificate.Subject"
    )
    proc = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
    lines = proc.stdout.strip().splitlines()
    if len(lines) < 2 or lines[0].strip() != "Valid" or not any(s in lines[1] for s in _MICROSOFT_SIGNERS):
        raise LocalError(f"la firma de {exe.name} no es una firma válida de Microsoft: {' | '.join(lines)}")


def _download_sysmon(folder: Path) -> Path:
    import urllib.request
    import zipfile

    archive = folder / "Sysmon.zip"
    try:
        with urllib.request.urlopen(SYSMON_URL, timeout=120) as response, archive.open("wb") as fh:
            shutil.copyfileobj(response, fh)
    except OSError as exc:
        raise LocalError(f"no se pudo descargar Sysmon de {SYSMON_URL}: {exc}") from exc
    with zipfile.ZipFile(archive) as zf:
        zf.extract("Sysmon64.exe", folder)
    exe = folder / "Sysmon64.exe"
    _verify_microsoft_signature(exe)
    return exe


def sysmon_install(config: Path = SYSMON_CONFIG, log: Callable[[str], None] = print) -> None:
    """Descarga Sysmon de Microsoft, comprueba su firma y lo instala con la configuración dada."""
    require_windows()
    _require_admin("instalar Sysmon")
    if sysmon_service():
        raise LocalError("Sysmon ya está instalado; para aplicar la configuración usa: winlog-hunter sysmon --actualizar")
    SYSMON_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    target_config = SYSMON_INSTALL_DIR / "sysmon.xml"
    shutil.copyfile(config, target_config)
    with tempfile.TemporaryDirectory() as tmp:
        log(f"Descargando Sysmon de {SYSMON_URL}...")
        exe = _download_sysmon(Path(tmp))
        log("Firma de Microsoft verificada. Instalando...")
        proc = _run([str(exe), "-accepteula", "-i", str(target_config)])
    if proc.returncode != 0 or not sysmon_service():
        raise LocalError("Sysmon no se pudo instalar:\n" + (proc.stdout + proc.stderr).strip())


def sysmon_update(config: Path = SYSMON_CONFIG) -> None:
    """Aplica la configuración de winlog-hunter a un Sysmon ya instalado."""
    require_windows()
    _require_admin("actualizar la configuración de Sysmon")
    service = sysmon_service()
    if not service:
        raise LocalError("Sysmon no está instalado; instálalo con: winlog-hunter sysmon --instalar")
    SYSMON_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    target_config = SYSMON_INSTALL_DIR / "sysmon.xml"
    shutil.copyfile(config, target_config)
    proc = _run([f"{service}.exe", "-c", str(target_config)])
    if proc.returncode != 0:
        raise LocalError("no se pudo aplicar la configuración:\n" + (proc.stdout + proc.stderr).strip())


def sysmon_uninstall() -> None:
    require_windows()
    _require_admin("desinstalar Sysmon")
    service = sysmon_service()
    if not service:
        raise LocalError("Sysmon no está instalado")
    proc = _run([f"{service}.exe", "-u"])
    if proc.returncode != 0 or sysmon_service():
        raise LocalError("no se pudo desinstalar Sysmon:\n" + (proc.stdout + proc.stderr).strip())


# --------------------------------------------------------------------------- #
# Auditoría de Windows
# --------------------------------------------------------------------------- #

# Subcategorías por GUID: auditpol acepta GUIDs en cualquier idioma de Windows.
AUDIT_SUBCATEGORIES = [
    ("{0CCE9215-69AE-11D9-BED3-505054503030}", "Inicio de sesión", "4624, 4625", "/success:enable /failure:enable"),
    ("{0CCE922B-69AE-11D9-BED3-505054503030}", "Creación de procesos", "4688", "/success:enable"),
    ("{0CCE9227-69AE-11D9-BED3-505054503030}", "Otros eventos de acceso a objetos", "4698", "/success:enable"),
    ("{0CCE9235-69AE-11D9-BED3-505054503030}", "Administración de cuentas de usuario", "4720", "/success:enable"),
    ("{0CCE9237-69AE-11D9-BED3-505054503030}", "Administración de grupos de seguridad", "4728, 4732", "/success:enable"),
]
AUDIT_REGISTRY = [
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging",
     "Script Block Logging de PowerShell (4104)"),
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled",
     "línea de comandos en el evento 4688"),
]
# Tamaño mínimo de los registros, para que quepan al menos 24 h de eventos.
AUDIT_LOG_SIZES = {
    "Security": 128 * 1024 * 1024,
    "Microsoft-Windows-PowerShell/Operational": 64 * 1024 * 1024,
    "Microsoft-Windows-Sysmon/Operational": 128 * 1024 * 1024,
}
AUDIT_BACKUP_DIR = SYSMON_INSTALL_DIR / "auditoria-original"


def audit_plan() -> list[list[str]]:
    """Comandos que activan la auditoría que necesitan las reglas."""
    commands = [["auditpol", "/set", f"/subcategory:{guid}", *flags.split()] for guid, _, _, flags in AUDIT_SUBCATEGORIES]
    commands += [["reg", "add", key, "/v", value, "/t", "REG_DWORD", "/d", "1", "/f"] for key, value, _ in AUDIT_REGISTRY]
    return commands


def _log_size(log: str) -> int | None:
    proc = _run(["wevtutil", "gl", log])
    for line in proc.stdout.splitlines():
        if line.strip().lower().startswith("maxsize:"):
            return int(line.split(":", 1)[1].strip())
    return None


def _registry_value(key: str, value: str) -> str | None:
    proc = _run(["reg", "query", key, "/v", value])
    for line in proc.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == value:
            return parts[-1]
    return None


def audit_enable(log: Callable[[str], None] = print) -> None:
    """Activa la auditoría de Windows que usan las reglas y guarda la configuración anterior."""
    require_windows()
    _require_admin("activar la auditoría")
    AUDIT_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup = AUDIT_BACKUP_DIR / "auditpol.csv"
    state = AUDIT_BACKUP_DIR / "estado.json"
    if not backup.exists():  # se guarda solo la primera vez: es el estado original del equipo
        proc = _run(["auditpol", "/backup", f"/file:{backup}"])
        if proc.returncode != 0:
            raise LocalError("no se pudo guardar la política de auditoría actual: " + " ".join(proc.stdout.split()))
        original = {
            "registro": {f"{k}\\{v}": _registry_value(k, v) for k, v, _ in AUDIT_REGISTRY},
            "tamaños": {name: _log_size(name) for name in AUDIT_LOG_SIZES},
        }
        state.write_text(json.dumps(original, indent=2), encoding="utf-8")
        log(f"Configuración original guardada en {AUDIT_BACKUP_DIR}")

    for command, (_, label, events, _) in zip(audit_plan(), AUDIT_SUBCATEGORIES):
        proc = _run(command)
        log(f"  {'OK   ' if proc.returncode == 0 else 'FALLO'} auditoría: {label} ({events})")
    for command, (_, _, label) in zip(audit_plan()[len(AUDIT_SUBCATEGORIES):], AUDIT_REGISTRY):
        proc = _run(command)
        log(f"  {'OK   ' if proc.returncode == 0 else 'FALLO'} {label}")
    for name, size in AUDIT_LOG_SIZES.items():
        current = _log_size(name)
        if current is None:
            continue
        if current < size:
            ok = _run(["wevtutil", "sl", name, f"/ms:{size}"]).returncode == 0
            log(f"  {'OK   ' if ok else 'FALLO'} tamaño de {name}: {current // 2**20} MB -> {size // 2**20} MB")


def audit_restore(log: Callable[[str], None] = print) -> None:
    """Deja la auditoría como estaba antes de 'auditoria --activar'."""
    require_windows()
    _require_admin("restaurar la auditoría")
    backup = AUDIT_BACKUP_DIR / "auditpol.csv"
    state = AUDIT_BACKUP_DIR / "estado.json"
    if not backup.exists() or not state.exists():
        raise LocalError("no hay configuración guardada: la auditoría no se activó con winlog-hunter")
    proc = _run(["auditpol", "/restore", f"/file:{backup}"])
    log(f"  {'OK   ' if proc.returncode == 0 else 'FALLO'} política de auditoría restaurada")
    original = json.loads(state.read_text(encoding="utf-8"))
    for key, value, label in AUDIT_REGISTRY:
        previous = original["registro"].get(f"{key}\\{value}")
        if previous is None:
            _run(["reg", "delete", key, "/v", value, "/f"])
        else:
            _run(["reg", "add", key, "/v", value, "/t", "REG_DWORD", "/d", str(int(previous, 0)), "/f"])
        log(f"  OK    {label} restaurado")
    for name, size in original["tamaños"].items():
        if size:
            _run(["wevtutil", "sl", name, f"/ms:{size}"])
    log("  OK    tamaños de los registros restaurados")
    shutil.rmtree(AUDIT_BACKUP_DIR, ignore_errors=True)


def audit_status() -> list[tuple[str, bool | None]]:
    """(descripción, activado) de cada ajuste. None si no se puede saber sin administrador."""
    require_windows()
    rows: list[tuple[str, bool | None]] = []
    for guid, label, events, flags in AUDIT_SUBCATEGORIES:
        proc = _run(["auditpol", "/get", f"/subcategory:{guid}", "/r"])
        if proc.returncode != 0:
            rows.append((f"auditoría: {label} ({events})", None))
            continue
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        setting = next(csv.reader([lines[-1]]), [""] * 5)[4].lower() if len(lines) > 1 else ""
        wanted_failure = "failure" in flags
        enabled = bool(setting) and setting not in ("no auditing", "sin auditoría") and (
            not wanted_failure or any(w in setting for w in ("and", " y ")))
        rows.append((f"auditoría: {label} ({events})", enabled))
    for key, value, label in AUDIT_REGISTRY:
        rows.append((label, _registry_value(key, value) in ("0x1", "1")))
    for name, size in AUDIT_LOG_SIZES.items():
        current = _log_size(name)
        if current is not None:
            rows.append((f"tamaño de {name} ({current // 2**20} MB)", current >= size))
    return rows


# --------------------------------------------------------------------------- #
# Desinstalación
# --------------------------------------------------------------------------- #


def uninstall_everything(
    keep_sysmon: bool = False, delete_reports: bool = False, log: Callable[[str], None] = print
) -> None:
    """Deshace todo lo que winlog-hunter cambió en el equipo (tarea, auditoría, Sysmon, PATH, datos)."""
    from . import pathfix

    require_windows()
    _require_admin("desinstalar winlog-hunter del equipo")

    if task_status():
        log(f"  {'OK   ' if unschedule() else 'FALLO'} tarea programada '{TASK_NAME}' eliminada")
    else:
        log("  -     no había tarea programada")

    if (AUDIT_BACKUP_DIR / "auditpol.csv").exists():
        audit_restore(log=lambda m: None)
        log("  OK    auditoría de Windows restaurada a la configuración original")
    else:
        log("  -     la auditoría no se había activado con winlog-hunter")

    if keep_sysmon:
        log("  -     Sysmon se conserva (--conservar-sysmon)")
    elif sysmon_service():
        sysmon_uninstall()
        log("  OK    Sysmon desinstalado")
    else:
        log("  -     Sysmon no estaba instalado")

    folder = pathfix.remove_added_folder()
    log(f"  OK    {folder} quitado del PATH" if folder else "  -     winlog-hunter no había tocado el PATH")

    shutil.rmtree(SYSMON_INSTALL_DIR, ignore_errors=True)
    if delete_reports:
        shutil.rmtree(default_output(), ignore_errors=True)
        log(f"  OK    informes borrados ({default_output()})")
    else:
        log(f"  -     los informes se conservan en {default_output()}")


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
