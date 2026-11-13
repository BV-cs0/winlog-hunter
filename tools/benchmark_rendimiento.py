"""Mide lectura, reglas y RAM del árbol de procesos, sin dependencias externas.

Ejemplo: .python\python.exe tools/benchmark_rendimiento.py --eventos 2000000
         .medidas/Application.evtx .medidas/System.evtx --procesos 1
Los datos sintéticos y los resultados se guardan en .medidas.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def leer_rango(path, rango):
    """Worker experimental: conserva los eventos filtrados de un rango nativo."""
    from winlog_hunter.parsers import Seleccion, consultas_xpath, _wevtutil_chunks, _events_from_xml_chunks
    from winlog_hunter.rules import planificar
    seleccion = Seleccion(planificar())
    events, warnings = [], []
    for query in consultas_xpath(seleccion.plan.ids, rango=rango):
        events.extend(_events_from_xml_chunks(_wevtutil_chunks(path, query), path, warnings.append, seleccion))
    return events, warnings


def cargar_troceado(path, procesos):
    """Experimento explícito; no activa troceo automático en el analizador."""
    import re
    from winlog_hunter.parsers import LoadResult, informacion_evtx
    info = informacion_evtx(path)
    last = subprocess.run(["wevtutil", "qe", str(path.resolve()), "/lf:true", "/rd:true", "/c:1", "/f:xml", "/uni:true"],
                          capture_output=True, check=True)
    match = re.search(r"<EventRecordID>(\d+)</EventRecordID>", last.stdout.decode("utf-16-le"))
    if not match:
        return LoadResult(files=1)
    primero, ultimo = info["oldestRecordNumber"], int(match[1])
    paso = max(1, (ultimo-primero+procesos)//procesos)
    rangos = [(a, min(a+paso, ultimo+1)) for a in range(primero, ultimo+1, paso)]
    result = LoadResult(files=1, leidos=info["numberOfLogRecords"])
    with ProcessPoolExecutor(max_workers=min(procesos, 61)) as pool:
        futures = [pool.submit(leer_rango, path, rango) for rango in rangos]
        for future in futures:
            events, warnings = future.result()
            result.events.extend(events)
            result.warnings.extend(warnings)
    result.events.sort(key=lambda e: (e.timestamp, e._record_id))
    result.descartados = result.leidos-len(result.events)
    return result


def generar(path: Path, cantidad: int):
    """90 % de ruido, 10 % de procesos normales y una instalación por 100.000."""
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for n in range(cantidad):
            record = {"EventID": 4634, "TimeCreated": "2026-11-03T09:10:00Z",
                      "Computer": "PC-PRUEBAS", "Channel": "Security",
                      "EventData": {"TargetUserName": "usuario", "LogonType": "3",
                                    "TargetLogonId": str(n)}}
            if n % 100000 == 0:
                record.update(EventID=7045, Channel="System", EventData={
                    "ServiceName": "ServicioPrueba", "ImagePath": "cmd.exe /c whoami", "AccountName": "SYSTEM"})
            elif n % 10 == 0:
                record.update(EventID=4688, EventData={"NewProcessName": r"C:\Windows\System32\notepad.exe",
                    "ParentProcessName": r"C:\Windows\explorer.exe", "CommandLine": "notepad.exe"})
            stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def worker(args):
    sys.path.insert(0, str(args.codigo or ROOT / "src"))
    from winlog_hunter.parsers import load_events
    from winlog_hunter.rules import run_rules
    inicio = time.perf_counter()
    if args.troceos_experimentales > 1:
        loaded = cargar_troceado(args.worker, args.troceos_experimentales)
    elif args.codigo:
        loaded = load_events([args.worker])
    else:
        from winlog_hunter.rules import planificar
        loaded = load_events([args.worker], plan=planificar(), procesos=args.procesos, estadisticas=True)
    parseo = time.perf_counter() - inicio
    findings = run_rules(loaded.events)
    total = time.perf_counter() - inicio
    result = {"fichero": str(args.worker), "eventos_utiles": len(loaded.events),
              "eventos_leidos": getattr(loaded, "leidos", len(loaded.events)),
              "parseo_s": parseo, "reglas_s": total-parseo, "total_s": total,
              "hallazgos": len(findings), "avisos": loaded.warnings}
    args.resultado.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")


class MemoriaWindows:
    """Conserva handles para consultar también el pico de workers terminados."""
    def __init__(self, pid):
        from ctypes import wintypes as w
        self.w = w
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        class Entry(ctypes.Structure):
            _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ProcessID", w.DWORD),
                        ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", w.DWORD),
                        ("cntThreads", w.DWORD), ("th32ParentProcessID", w.DWORD),
                        ("pcPriClassBase", w.LONG), ("dwFlags", w.DWORD), ("szExeFile", w.WCHAR*260)]
        class Counters(ctypes.Structure):
            _fields_ = [("cb", w.DWORD), ("PageFaultCount", w.DWORD)] + [
                (name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize",
                "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        self.Entry, self.Counters = Entry, Counters
        self.kernel.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
        self.kernel.CreateToolhelp32Snapshot.restype = w.HANDLE
        self.kernel.Process32FirstW.argtypes = [w.HANDLE, ctypes.POINTER(Entry)]
        self.kernel.Process32NextW.argtypes = [w.HANDLE, ctypes.POINTER(Entry)]
        self.kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.kernel.OpenProcess.restype = w.HANDLE
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.psapi.GetProcessMemoryInfo.argtypes = [w.HANDLE, ctypes.POINTER(Counters), w.DWORD]
        self.pids, self.handles, self.peaks = {pid}, {}, {}
        self.pico_simultaneo = 0
        self.pico_arbol = 0

    def medir(self):
        snapshot = self.kernel.CreateToolhelp32Snapshot(2, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = self.Entry()
            entry.dwSize = ctypes.sizeof(entry)
            relations = []
            ok = self.kernel.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                relations.append((entry.th32ProcessID, entry.th32ParentProcessID))
                ok = self.kernel.Process32NextW(snapshot, ctypes.byref(entry))
            for _ in range(4):
                self.pids.update(pid for pid, parent in relations if parent in self.pids)
        finally:
            self.kernel.CloseHandle(snapshot)
        activos = {pid for pid, _ in relations}
        current = 0
        for pid in set(self.handles) - activos:
            self.kernel.CloseHandle(self.handles.pop(pid))
        for pid in self.pids & activos:
            if pid not in self.handles:
                handle = self.kernel.OpenProcess(0x410, False, pid)
                if handle:
                    self.handles[pid] = handle
            handle = self.handles.get(pid)
            if handle:
                counters = self.Counters()
                counters.cb = ctypes.sizeof(counters)
                if self.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                    self.peaks[pid] = max(self.peaks.get(pid, 0), counters.PeakWorkingSetSize)
                    current += counters.WorkingSetSize
        self.pico_simultaneo = max(self.pico_simultaneo, current)
        # No sumar los picos de cientos de wevtutil que ya han terminado:
        # nunca coexistieron. Sí se cuentan padre, workers e hijos vivos.
        self.pico_arbol = max(self.pico_arbol, sum(peak for pid, peak in self.peaks.items() if pid in activos))
        return self.pico_arbol

    def close(self):
        for handle in self.handles.values():
            self.kernel.CloseHandle(handle)


def contar(path):
    if path.is_dir():
        return sum(contar(p) for p in path.iterdir() if p.is_dir() or p.suffix.lower() in {".evtx", ".jsonl"})
    if path.suffix.lower() == ".evtx":
        result = subprocess.run(["wevtutil", "gli", str(path.resolve()), "/lf:true"], capture_output=True, check=True)
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            if line.startswith("numberOfLogRecords:"):
                return int(line.split(":", 1)[1])
        raise RuntimeError("wevtutil gli no devolvió numberOfLogRecords")
    with path.open("rb") as stream:
        return sum(1 for line in stream if line.strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rutas", nargs="*", type=Path)
    parser.add_argument("--eventos", type=int, default=0, help="genera y mide un JSONL de N eventos")
    parser.add_argument("--procesos", type=int, default=1)
    parser.add_argument("--cli", action="store_true", help="mide analyze -f json completo, incluido arranque, reglas e informe")
    parser.add_argument("--troceos-experimentales", type=int, default=1,
                        help="mide rangos EventRecordID con N workers; solo EVTX, no activa la función en analyze")
    parser.add_argument("--codigo", type=Path, help="directorio src de la versión anterior para comparar")
    parser.add_argument("--json", type=Path, help="guarda las mediciones")
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--resultado", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        worker(args)
        return
    if os.name != "nt":
        parser.error("la medición de RAM de este benchmark requiere Windows")
    if args.eventos < 0 or args.procesos < 1 or args.troceos_experimentales < 1:
        parser.error("eventos no puede ser negativo y procesos debe ser al menos 1")
    if args.troceos_experimentales > 1 and (args.codigo or args.eventos or any(p.suffix.lower() != ".evtx" for p in args.rutas)):
        parser.error("el troceo experimental requiere solo EVTX y el código actual")
    if args.cli and args.troceos_experimentales > 1:
        parser.error("--cli no se combina con troceos experimentales")
    folder = ROOT / ".medidas"
    folder.mkdir(exist_ok=True)
    if args.eventos:
        synthetic = folder / f"sintetico-{args.eventos}.jsonl"
        if not synthetic.exists():
            generar(synthetic, args.eventos)
        args.rutas.append(synthetic)
    rows = []
    print("| Log | Eventos | Parseo ev/s | Total ev/s | Pico RAM árbol (MiB) |", flush=True)
    print("|---|---:|---:|---:|---:|", flush=True)
    for index, path in enumerate(args.rutas):
        output = folder / f"worker-{os.getpid()}-{index}.json"
        command = [sys.executable, str(Path(__file__).resolve()), "--worker", str(path),
                   "--resultado", str(output), "--procesos", str(args.procesos),
                   "--troceos-experimentales", str(args.troceos_experimentales)]
        if args.codigo:
            command.extend(["--codigo", str(args.codigo.resolve())])
        env = os.environ.copy()
        env.update(TEMP=str(folder), TMP=str(folder), PYTHONIOENCODING="utf-8")
        if args.cli:
            env.update(PYTHONPATH=str((args.codigo or ROOT / "src").resolve()), WINLOG_HUNTER_NO_PATH="1")
            command = [sys.executable, "-m", "winlog_hunter", "analyze", str(path), "-f", "json",
                       "-o", str(output), "--procesos", str(args.procesos)]
        inicio = time.perf_counter()
        proc = subprocess.Popen(command, env=env)
        memoria = MemoriaWindows(proc.pid)
        pico = 0
        try:
            while proc.poll() is None:
                pico = max(pico, memoria.medir())
                time.sleep(.02)
            pico = max(pico, memoria.medir())
        finally:
            memoria.close()
        if proc.returncode:
            raise RuntimeError(f"el proceso de medición terminó con código {proc.returncode}: {path}")
        elapsed = time.perf_counter() - inicio
        document = json.loads(output.read_text(encoding="utf-8"))
        if args.cli:
            row = dict(fichero=str(path), eventos=document["stats"]["eventos_leidos"],
                       eventos_utiles=document["stats"]["events"], parseo_s=document["stats"]["segundos"],
                       total_s=elapsed, hallazgos=len(document["findings"]), avisos=document["stats"]["warnings"])
        else:
            row = document
            row["eventos"] = contar(path)
        row.update(pico_ram_bytes=pico, procesos=args.procesos, cli=args.cli,
                   troceos_experimentales=args.troceos_experimentales,
                   pico_simultaneo_bytes=memoria.pico_simultaneo, codigo=str(args.codigo or ROOT / "src"))
        row["ev_s"] = row["eventos"] / row["parseo_s"]
        row["ev_s_total"] = row["eventos"] / row["total_s"]
        rows.append(row)
        print(f'| {path.name} | {row["eventos"]} | {row["ev_s"]:.0f} | {row["ev_s_total"]:.0f} | {pico/1024**2:.1f} |', flush=True)
    if args.json:
        args.json.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    main()
