"""Interfaz de línea de comandos."""

from __future__ import annotations

import argparse
import os
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
        description="Analiza logs de Windows (Security, System, Sysmon) y detecta actividad "
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
    return parser


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
    return _analyze(args)


if __name__ == "__main__":
    raise SystemExit(main())
