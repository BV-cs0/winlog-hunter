"""Deja el comando ``winlog-hunter`` disponible en Windows aunque pip no lo haya puesto en el PATH.

pip no puede modificar el PATH al instalar. Si el usuario ejecuta ``python -m winlog_hunter``
desde una consola y la carpeta donde pip dejó ``winlog-hunter.exe`` no está en el PATH,
se añade al PATH de su usuario (no al del sistema) y se le avisa una sola vez.
Se desactiva con la variable de entorno ``WINLOG_HUNTER_NO_PATH=1``.
"""

from __future__ import annotations

import os
import sys
import sysconfig
from pathlib import Path

EXE = "winlog-hunter.exe"
# Recuerda qué carpeta añadimos, para quitarla al desinstalar.
MARKER = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "winlog-hunter" / "path-anadido.txt"


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.expandvars(path.strip().strip('"')))) if path.strip() else ""


def scripts_dir() -> Path | None:
    """Carpeta donde pip instaló winlog-hunter.exe, o None."""
    candidates = [sysconfig.get_path("scripts")]
    try:
        candidates.append(sysconfig.get_path("scripts", f"{os.name}_user"))
    except KeyError:
        pass
    candidates.append(str(Path(sys.executable).parent / "Scripts"))
    for candidate in candidates:
        if candidate and (Path(candidate) / EXE).exists():
            return Path(candidate)
    return None


def on_path(folder: Path, *path_values: str) -> bool:
    target = _norm(str(folder))
    return any(_norm(entry) == target for value in path_values for entry in value.split(os.pathsep))


def _user_path() -> tuple[str, int]:
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
        try:
            value, kind = winreg.QueryValueEx(key, "Path")
            return value, kind
        except FileNotFoundError:
            return "", winreg.REG_EXPAND_SZ


def _set_user_path(value: str, kind: int) -> None:
    import ctypes
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Path", 0, kind, value)
    # Avisa a Windows (Explorer, consolas nuevas) de que el entorno cambió.
    result = ctypes.c_ulong()
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x0002, 5000, ctypes.byref(result))


def joined(current: str, folder: Path) -> str:
    return f"{current.rstrip(os.pathsep)}{os.pathsep}{folder}" if current.strip() else str(folder)


def without(current: str, folder: str) -> str:
    target = _norm(folder)
    return os.pathsep.join(e for e in current.split(os.pathsep) if e.strip() and _norm(e) != target)


def remove_added_folder() -> str | None:
    """Quita del PATH del usuario la carpeta que añadió winlog-hunter. Devuelve la carpeta o None."""
    if os.name != "nt" or not MARKER.exists():
        return None
    folder = MARKER.read_text(encoding="utf-8").strip()
    current, kind = _user_path()
    if on_path(Path(folder), current):
        _set_user_path(without(current, folder), kind)
    MARKER.unlink(missing_ok=True)
    try:
        MARKER.parent.rmdir()
    except OSError:
        pass
    return folder


def ensure_command_available() -> None:
    """Añade la carpeta Scripts al PATH del usuario si hace falta. Nunca interrumpe el programa."""
    try:
        if os.name != "nt" or os.environ.get("WINLOG_HUNTER_NO_PATH"):
            return
        # Solo en una consola interactiva: nunca en la tarea programada (SYSTEM, pythonw) ni en scripts.
        if not (sys.stdin and sys.stdin.isatty() and sys.stderr):
            return
        folder = scripts_dir()
        if folder is None or on_path(folder, os.environ.get("PATH", "")):
            return
        current, kind = _user_path()
        if on_path(folder, current):
            return  # ya añadida: solo falta abrir una consola nueva
        _set_user_path(joined(current, folder), kind)
        MARKER.parent.mkdir(parents=True, exist_ok=True)
        MARKER.write_text(str(folder), encoding="utf-8")
        print(
            f"winlog-hunter: he añadido {folder} al PATH de tu usuario.\n"
            "Desde la próxima consola que abras podrás escribir simplemente 'winlog-hunter'.\n",
            file=sys.stderr,
        )
    except Exception:
        return
