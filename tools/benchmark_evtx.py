"""Mide la cobertura de winlog-hunter contra EVTX-ATTACK-SAMPLES.

Uso:
    python tools/benchmark_evtx.py RUTA_AL_DATASET [--json salida.json] [--detalle]

Un fichero cuenta como detectado si salta al menos una regla distinta de
WLH-005 (registro borrado): el autor del dataset vació los logs antes de
grabar cada ataque, así que esa regla salta casi siempre y no dice nada.

Con --json guarda, por fichero, las reglas que saltan; sirve para comparar
dos versiones y ver qué se gana o se pierde.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from winlog_hunter.parsers import load_events  # noqa: E402
from winlog_hunter.rules import run_rules  # noqa: E402

IGNORED = {"WLH-005"}
TACTICS = {
    "Credential Access": "Credential Access",
    "Lateral Movement": "Lateral Movement",
    "Persistence": "Persistence",
    "Execution": "Execution",
    "AutomatedTestingTools": "Herramientas de pruebas automatizadas",
    "Privilege Escalation": "Privilege Escalation",
    "Defense Evasion": "Defense Evasion",
    "Discovery": "Discovery",
    "Command and Control": "Command and Control",
}


def tactic(dataset: Path, path: Path) -> str:
    top = path.relative_to(dataset).parts[0]
    return TACTICS.get(top, "Otros")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--json", type=Path, help="guarda el resultado por fichero")
    parser.add_argument("--detalle", action="store_true", help="lista los ficheros no detectados")
    args = parser.parse_args()

    files = sorted(args.dataset.rglob("*.evtx"))
    per_file: dict[str, list[str]] = {}
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for path in files:
        rel = path.relative_to(args.dataset).as_posix()
        try:
            events = load_events([path]).events
            rules = sorted({f.rule_id for f in run_rules(events)})
        except Exception as exc:  # un fichero roto no debe parar la medición
            print(f"aviso: {rel}: {exc}", file=sys.stderr)
            rules = []
        per_file[rel] = rules
        bucket = totals[tactic(args.dataset, path)]
        bucket[0] += 1
        if set(rules) - IGNORED:
            bucket[1] += 1

    order = list(dict.fromkeys(list(TACTICS.values()) + ["Otros"]))
    print("| Táctica | Ficheros | Detectados |")
    print("|---|---|---|")
    total = [0, 0]
    for name in order:
        if name in totals:
            n, d = totals[name]
            total[0] += n
            total[1] += d
            print(f"| {name} | {n} | {d} |")
    print(f"| **Total** | **{total[0]}** | **{total[1]}** |")

    if args.detalle:
        print("\nNo detectados:")
        for rel, rules in per_file.items():
            if not set(rules) - IGNORED:
                print(f"  {rel}")

    if args.json:
        args.json.write_text(json.dumps(per_file, indent=1, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
