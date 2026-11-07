"""Interfaz de línea de comandos."""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__
from .models import SEVERITIES, SEVERITY_ORDER
from .parsers import load_events
from .report import RENDERERS, SEVERITY_LABEL, Stats, render_console
from .rules import RULES, Config, run_rules

FORMATS = ("console", "json", "markdown", "html")
_EXTENSION_FORMAT = {".json": "json", ".md": "markdown", ".markdown": "markdown", ".html": "html", ".htm": "html"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="winlog-hunter",
        description="Analiza logs de Windows (Security, System, Sysmon, PowerShell) y detecta actividad "
        "sospechosa mapeada a MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analiza ficheros o carpetas de logs")
    analyze.add_argument("paths", nargs="+", type=Path, help=".evtx, .xml (wevtutil), .jsonl/.json o carpetas")
    analyze.add_argument("-f", "--format", choices=FORMATS, help="formato de salida (por defecto, según -o o consola)")
    analyze.add_argument("-o", "--output", type=Path, help="fichero donde guardar el informe")
    analyze.add_argument("--min-severity", choices=SEVERITIES, default="low", help="oculta hallazgos por debajo")
    analyze.add_argument("--rules", help="IDs de reglas separados por comas, p. ej. WLH-001,WLH-003")
    analyze.add_argument("--fail-on", choices=SEVERITIES, help="sale con código 1 si hay hallazgos de esa severidad o más")
    analyze.add_argument("--threshold", type=int, default=5, help="fallos para considerar fuerza bruta (5)")
    analyze.add_argument("--spray-accounts", type=int, default=5, help="cuentas distintas para password spraying (5)")
    analyze.add_argument("--window", type=float, default=5, help="ventana de correlación en minutos (5)")
    analyze.add_argument("--lateral-hosts", type=int, default=3, help="equipos distintos para movimiento lateral (3)")
    analyze.add_argument("--no-color", action="store_true", help="desactiva los colores en consola")

    sub.add_parser("rules", help="lista las reglas de detección")

    notify_choices = (*SEVERITIES, "nunca")
    local = sub.add_parser(
        "equipo",
        help="analiza los logs de este equipo (Windows) y abre el informe",
        description="Exporta Security, System, PowerShell y Sysmon de las últimas horas, los analiza y guarda "
        "el informe en Documentos\\winlog-hunter. Ejecútalo como administrador para incluir Security.",
    )
    local.add_argument("--horas", type=int, default=24, help="horas hacia atrás que se analizan (24)")
    local.add_argument("--salida", type=Path, help="carpeta de los informes (Documentos\\winlog-hunter)")
    local.add_argument("--conservar-dias", type=int, default=30, help="borra informes más antiguos (30)")
    local.add_argument("--avisar-desde", choices=notify_choices, default="critical",
                       help="aviso en pantalla desde esta severidad (critical)")
    local.add_argument("--sin-abrir", action="store_true", help="no abre el informe al terminar")

    sched = sub.add_parser(
        "programar",
        help="programa el análisis diario del equipo (Windows, como administrador)",
        description="Crea la tarea programada 'winlog-hunter diario', que ejecuta 'winlog-hunter equipo' cada día "
        "como SYSTEM. Si el equipo está apagado a esa hora, se ejecuta al encenderlo.",
    )
    sched.add_argument("--hora", default="09:00", help="hora del día, HH:MM (09:00)")
    sched.add_argument("--horas", type=int, default=24, help="horas de logs que analiza cada día (24)")
    sched.add_argument("--salida", type=Path, help="carpeta de los informes (Documentos\\winlog-hunter)")
    sched.add_argument("--avisar-desde", choices=notify_choices, default="critical",
                       help="aviso en pantalla desde esta severidad (critical)")
    group = sched.add_mutually_exclusive_group()
    group.add_argument("--ahora", action="store_true", help="lanza la tarea ya, sin esperar")
    group.add_argument("--quitar", action="store_true", help="elimina la tarea")
    group.add_argument("--estado", action="store_true", help="muestra si la tarea existe")

    sysmon = sub.add_parser(
        "sysmon",
        help="instala o actualiza Sysmon con la configuración de winlog-hunter (Windows, como administrador)",
        description="Descarga Sysmon de la web oficial de Microsoft, comprueba su firma y lo instala con una "
        "configuración pensada para las reglas de winlog-hunter. Al instalarlo se acepta la licencia de Sysinternals.",
    )
    action = sysmon.add_mutually_exclusive_group(required=True)
    action.add_argument("--instalar", action="store_true", help="descarga e instala Sysmon")
    action.add_argument("--actualizar", action="store_true", help="aplica la configuración a un Sysmon ya instalado")
    action.add_argument("--desinstalar", action="store_true", help="desinstala Sysmon")
    action.add_argument("--estado", action="store_true", help="muestra si Sysmon está instalado")
    action.add_argument("--config", action="store_true", help="muestra la ruta de la configuración incluida")

    audit = sub.add_parser(
        "auditoria",
        help="activa la auditoría de Windows que necesitan las reglas (Windows, como administrador)",
        description="Activa la auditoría de creación de procesos (con línea de comandos), tareas programadas, "
        "cuentas, grupos y servicios, el Script Block Logging de PowerShell, y amplía el tamaño de los registros. "
        "Guarda la configuración original para poder restaurarla.",
    )
    audit_action = audit.add_mutually_exclusive_group(required=True)
    audit_action.add_argument("--activar", action="store_true", help="activa la auditoría")
    audit_action.add_argument("--restaurar", action="store_true", help="vuelve a la configuración original")
    audit_action.add_argument("--estado", action="store_true", help="muestra qué está activado")
    return parser


def _audit(args: argparse.Namespace) -> int:
    from . import local

    try:
        local.require_windows()
        if args.estado:
            rows = local.audit_status()
            marks = {True: "[x]", False: "[ ]", None: "[?]"}
            for label, enabled in rows:
                print(f"{marks[enabled]} {label}")
            if any(enabled is None for _, enabled in rows):
                print("[?] = hace falta administrador para comprobarlo", file=sys.stderr)
            return 0 if all(rows_enabled for _, rows_enabled in rows) else 1
        if args.activar:
            local.audit_enable()
            print("Auditoría activada. Para volver atrás: winlog-hunter auditoria --restaurar")
        else:
            local.audit_restore()
            print("Auditoría restaurada a la configuración original.")
    except local.LocalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _sysmon(args: argparse.Namespace) -> int:
    from . import local

    try:
        if args.config:
            print(local.SYSMON_CONFIG)
            return 0
        local.require_windows()
        if args.estado:
            service = local.sysmon_service()
            print(f"Sysmon instalado (servicio {service})." if service else "Sysmon no está instalado.")
            return 0 if service else 1
        if args.instalar:
            local.sysmon_install()
            print("Sysmon instalado. Los eventos nuevos van al registro Microsoft-Windows-Sysmon/Operational.")
            print("Pruébalo con:  winlog-hunter equipo")
        elif args.actualizar:
            local.sysmon_update()
            print("Configuración de Sysmon actualizada.")
        else:
            local.sysmon_uninstall()
            print("Sysmon desinstalado.")
    except local.LocalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _local(args: argparse.Namespace) -> int:
    from . import local

    if not 1 <= args.horas <= 8760 or args.conservar_dias < 1:
        print("error: --horas debe estar entre 1 y 8760 y --conservar-dias ser al menos 1", file=sys.stderr)
        return 2
    try:
        local.require_windows()
        if not local.is_admin():
            print("Aviso: sin administrador no se puede leer el log Security.", file=sys.stderr)
        result = local.analyze_this_computer(
            hours=args.horas,
            output=args.salida,
            keep_days=args.conservar_dias,
            notify_from=None if args.avisar_desde == "nunca" else args.avisar_desde,
        )
    except local.LocalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not args.sin_abrir:
        try:
            os.startfile(result.html)  # type: ignore[attr-defined]
        except OSError:
            pass
    return result.exit_code


def _schedule(args: argparse.Namespace) -> int:
    from . import local

    try:
        if args.estado:
            status = local.task_status()
            print(f"Tarea '{local.TASK_NAME}': {status}" if status else
                  f"La tarea '{local.TASK_NAME}' no existe (o hace falta administrador para verla).")
            return 0 if status else 1
        if args.quitar:
            removed = local.unschedule()
            print(f"Tarea '{local.TASK_NAME}' eliminada." if removed else f"La tarea '{local.TASK_NAME}' no existía.")
            return 0
        if args.ahora:
            local.run_now()
            print(f"Tarea lanzada. El informe aparecerá en unos segundos en {args.salida or local.default_output()}")
            return 0
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", args.hora):
            print("error: --hora debe tener el formato HH:MM, p. ej. 21:30", file=sys.stderr)
            return 2
        if not 1 <= args.horas <= 8760:
            print("error: --horas debe estar entre 1 y 8760", file=sys.stderr)
            return 2
        output = args.salida or local.default_output()
        local.schedule(args.hora, args.horas, output, "nunca" if args.avisar_desde == "nunca" else args.avisar_desde)
    except local.LocalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Tarea '{local.TASK_NAME}' creada: cada día a las {args.hora}, últimas {args.horas} h.")
    print(f"Informes en: {output}")
    print("Para probarla ya:  winlog-hunter programar --ahora")
    print("Para quitarla:     winlog-hunter programar --quitar")
    return 0


def _enable_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _list_rules() -> int:
    for r in RULES:
        print(f"{r.id}  [{SEVERITY_LABEL[r.severity]}]  {', '.join(r.mitre)}")
        print(f"         {r.title}: {r.description}")
    return 0


def _analyze(args: argparse.Namespace) -> int:
    known = {r.id for r in RULES}
    only = None
    if args.rules:
        only = {rid.strip().upper() for rid in args.rules.split(",") if rid.strip()}
        unknown = only - known
        if unknown:
            print(f"error: reglas desconocidas: {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
    for name in ("threshold", "spray_accounts", "lateral_hosts"):
        if getattr(args, name) < 1:
            print(f"error: --{name.replace('_', '-')} debe ser al menos 1", file=sys.stderr)
            return 2
    if args.window <= 0:
        print("error: --window debe ser mayor que 0", file=sys.stderr)
        return 2

    try:
        loaded = load_events(args.paths)
    except (FileNotFoundError, PermissionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not loaded.events and loaded.warnings:
        print("error: no se pudo leer ningún evento:", file=sys.stderr)
        for warning in loaded.warnings[:10]:
            print(f"  - {warning}", file=sys.stderr)
        return 2

    config = Config(
        window=timedelta(minutes=args.window),
        brute_force_threshold=args.threshold,
        spray_min_accounts=args.spray_accounts,
        lateral_min_hosts=args.lateral_hosts,
    )
    all_findings = run_rules(loaded.events, config, only)
    minimum = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in all_findings if f.rank >= minimum]

    stats = Stats(
        events=len(loaded.events),
        files=loaded.files,
        first_event=loaded.events[0].timestamp if loaded.events else None,
        last_event=loaded.events[-1].timestamp if loaded.events else None,
        warnings=loaded.warnings,
    )

    fmt = args.format or (_EXTENSION_FORMAT.get(args.output.suffix.lower(), "console") if args.output else "console")
    if fmt == "console":
        color = (
            not args.no_color
            and args.output is None
            and "NO_COLOR" not in os.environ
            and sys.stdout.isatty()
            and _enable_ansi()
        )
        text = render_console(findings, stats, color=color)
    else:
        text = RENDERERS[fmt](findings, stats)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        print(f"Informe {fmt} guardado en {args.output} ({len(findings)} hallazgos)", file=sys.stderr)
    else:
        print(text)

    # --fail-on es independiente de lo que se muestra: se evalúa sobre todos los hallazgos.
    if args.fail_on and any(f.rank >= SEVERITY_ORDER[args.fail_on] for f in all_findings):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        return _list_rules()
    if args.command == "equipo":
        return _local(args)
    if args.command == "programar":
        return _schedule(args)
    if args.command == "sysmon":
        return _sysmon(args)
    if args.command == "auditoria":
        return _audit(args)
    return _analyze(args)


if __name__ == "__main__":
    raise SystemExit(main())
