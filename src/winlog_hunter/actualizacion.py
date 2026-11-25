"""Aviso de versión nueva publicada en PyPI.

Solo informa: nunca instala ni toca el entorno de Python de quien lo usa. El aviso es una
línea por stderr al arrancar, una sola vez por versión nueva. La consulta a PyPI va en un
hilo aparte, como mucho una vez al día y con un tiempo límite corto. Si falla, no pasa nada.
No se hace nada sin terminal interactiva (tarea programada, tuberías, CI) ni con la
variable de entorno WINLOG_HUNTER_SIN_AVISO_VERSION.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable, TextIO

URL_PYPI = "https://pypi.org/pypi/winlog-hunter/json"
TIEMPO_LIMITE = 3
INTERVALO = 24 * 3600
VARIABLE_DESACTIVAR = "WINLOG_HUNTER_SIN_AVISO_VERSION"
_ESTABLE = re.compile(r"\d+(?:\.\d+){0,3}")


def version_a_tupla(version: str) -> tuple[int, ...] | None:
    """'0.6.0' -> (0, 6). Las versiones previas ('0.7.0rc1', '1.0.dev2') o raras dan None."""
    if not isinstance(version, str) or not _ESTABLE.fullmatch(version.strip()):
        return None
    partes = [int(n) for n in version.strip().split(".")]
    while len(partes) > 1 and partes[-1] == 0:
        partes.pop()
    return tuple(partes)


def hay_version_nueva(actual: str, ultima: str) -> bool:
    nueva, instalada = version_a_tupla(ultima), version_a_tupla(actual)
    return nueva is not None and instalada is not None and nueva > instalada


def carpeta_estado() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "winlog-hunter"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "winlog-hunter"


def _leer(ruta: Path) -> dict:
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
        return datos if isinstance(datos, dict) else {}
    except Exception:
        return {}


def _guardar(ruta: Path, estado: dict) -> None:
    try:
        ruta.parent.mkdir(parents=True, exist_ok=True)
        ruta.write_text(json.dumps(estado), encoding="utf-8")
    except Exception:
        pass


def consultar_pypi(timeout: float = TIEMPO_LIMITE) -> str | None:
    """Última versión estable publicada, o None ante cualquier fallo (red, PyPI, respuesta rara)."""
    try:
        with urllib.request.urlopen(URL_PYPI, timeout=timeout) as resp:
            version = json.loads(resp.read(1_000_000).decode("utf-8"))["info"]["version"]
    except Exception:
        return None
    return version if version_a_tupla(version) is not None else None


def mensaje(actual: str, ultima: str) -> str:
    return (f"Hay una versión nueva de winlog-hunter: {ultima} (tienes {actual}). "
            f"Para actualizar: pip install -U winlog-hunter")


def iniciar(actual: str, flujo: TextIO | None = None, ruta: Path | None = None,
            ahora: Callable[[], float] = time.time,
            consultar: Callable[[], str | None] = consultar_pypi) -> threading.Thread | None:
    """Muestra el aviso pendiente (si lo hay) y, si toca, lanza la consulta en segundo plano.
    Devuelve el hilo lanzado (o None). Nunca lanza excepciones ni espera a la red."""
    try:
        flujo = flujo or sys.stderr
        if os.environ.get(VARIABLE_DESACTIVAR) or not flujo.isatty():
            return None
        ruta = ruta or carpeta_estado() / "version.json"
        estado = _leer(ruta)
        ultima = str(estado.get("ultima", ""))
        if hay_version_nueva(actual, ultima) and estado.get("avisado") != ultima:
            print(mensaje(actual, ultima), file=flujo)
            estado["avisado"] = ultima
            _guardar(ruta, estado)
        comprobado = estado.get("comprobado")
        if isinstance(comprobado, (int, float)) and 0 <= ahora() - comprobado < INTERVALO:
            return None

        def tarea() -> None:
            try:
                encontrada = consultar()
                if encontrada:
                    nuevo = _leer(ruta)
                    nuevo.update(comprobado=ahora(), ultima=encontrada)
                    _guardar(ruta, nuevo)
            except Exception:
                pass

        hilo = threading.Thread(target=tarea, name="winlog-hunter-version", daemon=True)
        hilo.start()
        return hilo
    except Exception:
        return None
