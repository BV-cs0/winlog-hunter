"""Lectura y normalización de logs de Windows.

Formatos admitidos:
  * .evtx  -> ficheros nativos del Visor de eventos (requiere ``python-evtx``).
  * .xml   -> salida de ``wevtutil qe <log> /f:xml`` o eventos exportados en XML.
  * .jsonl / .ndjson / .json -> un evento JSON por línea, un array JSON o un único objeto.

Todo lo que se lee de un log se trata como dato no confiable: no se resuelven
entidades XML y se rechazan documentos con DOCTYPE.
"""

from __future__ import annotations

import json
import locale
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from .models import Event

SUPPORTED_SUFFIXES = {".evtx", ".xml", ".jsonl", ".ndjson", ".json"}

Warn = Callable[[str], None]


class ParseError(ValueError):
    """Un registro no se pudo interpretar como evento de Windows."""


@dataclass
class LoadResult:
    events: list[Event] = field(default_factory=list)
    files: int = 0
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Fechas
# --------------------------------------------------------------------------- #

_MS_DATE = re.compile(r"/Date\((-?\d+)\)/")
_FRACTION = re.compile(r"\.(\d+)")


def parse_timestamp(value: Any) -> datetime:
    """Convierte las variantes habituales de fecha de Windows a datetime UTC."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if value > 1e11 else value  # epoch en ms o en s
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        ms = _MS_DATE.fullmatch(text)  # ConvertTo-Json de PowerShell 5.1
        if ms:
            return datetime.fromtimestamp(int(ms.group(1)) / 1000, tz=timezone.utc)
        if text[-1:] in ("Z", "z"):
            text = text[:-1] + "+00:00"
        # Windows usa 7 decimales; fromisoformat (3.10) solo acepta 3 o 6.
        text = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ParseError(f"fecha no reconocida: {value!r}") from exc
    else:
        raise ParseError(f"fecha no reconocida: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #

_ID_KEYS = ("EventID", "EventId", "Id", "event_id", "eventId", "event.code")
_TIME_KEYS = ("TimeCreated", "SystemTime", "@timestamp", "timestamp", "time", "UtcTime")
_COMPUTER_KEYS = ("Computer", "MachineName", "computer", "hostname", "host")
_CHANNEL_KEYS = ("Channel", "LogName", "channel", "log_name")
_PROVIDER_KEYS = ("Provider", "ProviderName", "provider", "SourceName")
_NESTED_KEYS = ("EventData", "event_data", "UserData", "data")


def _pop_first(record: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record.pop(key)
    return None


def _scalar(value: Any) -> Any:
    """Acepta valores tipo {'#text': '4625'} de conversores XML->JSON."""
    if isinstance(value, dict):
        for key in ("#text", "value", "Value", "Name"):
            if key in value:
                return value[key]
    return value


_WINLOG_FIELDS = {
    "event_id": "EventID",
    "channel": "Channel",
    "computer_name": "Computer",
    "provider_name": "Provider",
}


def _flatten_beats(rec: dict[str, Any]) -> dict[str, Any]:
    """Adapta el formato de Winlogbeat/ECS (winlog.*, host.name, event.code) al plano."""
    winlog = rec.pop("winlog", None)
    if isinstance(winlog, dict):
        for source, target in _WINLOG_FIELDS.items():
            if winlog.get(source) not in (None, ""):
                rec.setdefault(target, winlog[source])
        for key in ("event_data", "user_data"):
            if isinstance(winlog.get(key), dict):
                rec.setdefault("EventData", {})
                if isinstance(rec["EventData"], dict):
                    for k, v in winlog[key].items():
                        rec["EventData"].setdefault(k, v)
    host = rec.get("host")
    if isinstance(host, dict):
        rec.pop("host")
        name = host.get("name") or host.get("hostname")
        if name:
            rec.setdefault("Computer", name)
    event = rec.get("event")
    if isinstance(event, dict):
        rec.pop("event")
        if event.get("code") not in (None, ""):
            rec.setdefault("EventID", event["code"])
        if event.get("provider"):
            rec.setdefault("Provider", event["provider"])
    return rec


def event_from_dict(record: dict[str, Any]) -> Event:
    if not isinstance(record, dict):
        raise ParseError("el registro no es un objeto JSON")
    rec = _flatten_beats(dict(record))
    event_id = _scalar(_pop_first(rec, _ID_KEYS))
    timestamp = _scalar(_pop_first(rec, _TIME_KEYS))
    if event_id is None or timestamp is None:
        raise ParseError("falta EventID o TimeCreated")
    try:
        event_id = int(event_id)
    except (TypeError, ValueError) as exc:
        raise ParseError(f"EventID no numérico: {event_id!r}") from exc

    computer = _scalar(_pop_first(rec, _COMPUTER_KEYS)) or ""
    channel = _scalar(_pop_first(rec, _CHANNEL_KEYS)) or ""
    provider = _scalar(_pop_first(rec, _PROVIDER_KEYS)) or ""

    data: dict[str, str] = {}
    for key in _NESTED_KEYS:
        nested = rec.pop(key, None)
        if isinstance(nested, dict):
            for k, v in nested.items():
                if not isinstance(v, (dict, list)):
                    data[str(k)] = "" if v is None else str(v)
    for k, v in rec.items():
        if not isinstance(v, (dict, list)):
            data.setdefault(str(k), "" if v is None else str(v))

    return Event(
        timestamp=parse_timestamp(timestamp),
        event_id=event_id,
        computer=str(computer),
        channel=str(channel),
        provider=str(provider),
        data=data,
    )


def load_json(path: Path, warn: Warn) -> Iterator[Event]:
    text = _read_text(path)
    stripped = text.lstrip()

    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None  # probablemente JSONL: se lee línea a línea
        if isinstance(parsed, dict):
            parsed = [parsed]
        if isinstance(parsed, list):
            for index, record in enumerate(parsed, 1):
                try:
                    yield event_from_dict(record)
                except ParseError as exc:
                    warn(f"{path.name}[{index}]: {exc}")
            return
        if stripped.startswith("["):
            warn(f"{path.name}: JSON inválido")
            return

    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            yield event_from_dict(json.loads(line))
        except (json.JSONDecodeError, ParseError) as exc:
            warn(f"{path.name}:{number}: {exc}")


# --------------------------------------------------------------------------- #
# XML / EVTX
# --------------------------------------------------------------------------- #

_XML_DECL = re.compile(r"<\?xml[^>]*\?>")


def _strip_namespaces(root: ET.Element) -> None:
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]


def event_from_xml(element: ET.Element) -> Event:
    """Convierte un nodo <Event> (sin namespaces) en Event."""
    system = element.find("System")
    if system is None:
        raise ParseError("evento sin nodo <System>")
    event_id = (system.findtext("EventID") or "").strip()
    created = system.find("TimeCreated")
    if not event_id or created is None or not created.get("SystemTime"):
        raise ParseError("falta EventID o TimeCreated")
    provider = system.find("Provider")

    data: dict[str, str] = {}
    event_data = element.find("EventData")
    if event_data is not None:
        for index, node in enumerate(event_data.findall("Data")):
            name = node.get("Name") or f"Data{index}"
            data[name] = (node.text or "").strip()
    user_data = element.find("UserData")
    if user_data is not None:
        for node in user_data.iter():
            if node is not user_data and len(node) == 0:
                data.setdefault(node.tag, (node.text or "").strip())

    try:
        numeric_id = int(event_id)
    except ValueError as exc:
        raise ParseError(f"EventID no numérico: {event_id!r}") from exc

    return Event(
        timestamp=parse_timestamp(created.get("SystemTime")),
        event_id=numeric_id,
        computer=(system.findtext("Computer") or "").strip(),
        channel=(system.findtext("Channel") or "").strip(),
        provider=provider.get("Name", "") if provider is not None else "",
        data=data,
    )


def load_xml(path: Path, warn: Warn) -> Iterator[Event]:
    yield from _events_from_xml_text(_read_text(path), path, warn)


def _events_from_xml_text(text: str, path: Path, warn: Warn) -> Iterator[Event]:
    if "<!DOCTYPE" in text.upper():
        warn(f"{path.name}: se rechaza XML con DOCTYPE (posible ataque de entidades)")
        return
    # wevtutil concatena <Event> sin nodo raíz: se envuelve siempre.
    body = _XML_DECL.sub("", text)
    try:
        root = ET.fromstring(f"<WlhRoot>{body}</WlhRoot>")
    except ET.ParseError as exc:
        warn(f"{path.name}: XML inválido ({exc})")
        return
    _strip_namespaces(root)
    for index, element in enumerate(root.iter("Event"), 1):
        try:
            yield event_from_xml(element)
        except ParseError as exc:
            warn(f"{path.name}[evento {index}]: {exc}")


def _wevtutil_xml(path: Path) -> str | None:
    """En Windows, convierte el .evtx a XML con wevtutil (cientos de veces más rápido
    que python-evtx y lee registros que este no entiende). None si no está disponible."""
    if os.name != "nt" or shutil.which("wevtutil") is None:
        return None
    try:
        proc = subprocess.run(
            ["wevtutil", "qe", str(path.resolve()), "/lf:true", "/f:xml"],
            capture_output=True,
            timeout=900,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return proc.stdout.decode("utf-8")
    except UnicodeDecodeError:
        # wevtutil escribe en la página de códigos ANSI del sistema (p. ej. cp1252).
        return proc.stdout.decode(locale.getpreferredencoding(False), errors="replace")


def load_evtx(path: Path, warn: Warn) -> Iterator[Event]:
    text = _wevtutil_xml(path)
    if text is not None:
        yield from _events_from_xml_text(text, path, warn)
        return
    try:
        from Evtx.Evtx import Evtx  # type: ignore[import-not-found]
    except ImportError:
        warn(
            f"{path.name}: para leer .evtx fuera de Windows instala 'python-evtx' "
            "(pip install winlog-hunter[evtx]) o exporta el log con wevtutil a XML"
        )
        return
    with Evtx(str(path)) as log:
        for index, record in enumerate(log.records(), 1):
            try:
                element = ET.fromstring(record.xml())
                _strip_namespaces(element)
                yield event_from_xml(element)
            except (ET.ParseError, ParseError, Exception) as exc:  # registros corruptos
                warn(f"{path.name}[registro {index}]: {exc}")


# --------------------------------------------------------------------------- #
# Entrada principal
# --------------------------------------------------------------------------- #

_LOADERS = {
    ".evtx": load_evtx,
    ".xml": load_xml,
    ".json": load_json,
    ".jsonl": load_json,
    ".ndjson": load_json,
}


def _read_text(path: Path) -> str:
    """Lee texto detectando el BOM (PowerShell 5.1 escribe UTF-16 con '>')."""
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig", errors="replace")


def iter_files(paths: Iterable[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(
                p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES
            )
        elif path.is_file():
            yield path
        else:
            raise FileNotFoundError(f"no existe: {path}")


def load_events(paths: Iterable[Path]) -> LoadResult:
    result = LoadResult()
    for path in iter_files(paths):
        result.files += 1
        loader = _LOADERS.get(path.suffix.lower(), load_json)
        result.events.extend(loader(path, result.warnings.append))
    result.events.sort(key=lambda e: e.timestamp)
    return result
