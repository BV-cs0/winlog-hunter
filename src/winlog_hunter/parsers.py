"""Lectura y normalización de logs de Windows.

Formatos admitidos:
  * .evtx  -> wevtutil en Windows; ``python-evtx`` opcional en otros sistemas.
  * .xml   -> salida de ``wevtutil qe <log> /f:xml`` o eventos exportados en XML.
  * .jsonl / .ndjson / .json -> un evento JSON por línea, un array JSON o un único objeto.

Todo lo que se lee de un log se trata como dato no confiable: no se resuelven
entidades XML y se rechazan documentos con DOCTYPE.
"""

from __future__ import annotations

import json
import codecs
import io
import sys
import time
from concurrent.futures import ProcessPoolExecutor
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
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
    leidos: int = 0
    descartados: int = 0
    segundos: float = 0.0


@dataclass
class Seleccion:
    """Filtra antes de construir Event y cuenta los registros examinados."""
    plan: Any = None
    desde: datetime | None = None
    hasta: datetime | None = None
    leidos: int = 0
    descartados: int = 0
    progreso: bool = False
    estadisticas: bool = False
    inicio: float = field(default_factory=time.perf_counter)

    def previo(self, event_id: int) -> bool:
        self.leidos += 1
        if self.progreso and self.leidos % 100000 == 0:
            elapsed = time.perf_counter() - self.inicio
            print(f"{self.leidos} eventos leídos · {self.leidos-self.descartados} útiles · "
                  f"{self.leidos / max(elapsed, .000001):.0f} ev/s", file=sys.stderr)
        if self.plan is not None and event_id not in self.plan.ids:
            self.descartados += 1
            return False
        return True

    def posterior(self, event: Event) -> bool:
        if ((self.desde and event.timestamp < self.desde) or
                (self.hasta and event.timestamp > self.hasta) or
                (self.plan is not None and not self.plan.acepta(event))):
            self.descartados += 1
            return False
        return True


def limite_temporal(value: str, ahora: datetime | None = None) -> datetime:
    """Lee una fecha ISO o una distancia hacia atrás (24h, 7d)."""
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([hd])", value.strip(), re.I)
    if match:
        horas = float(match[1]) * (24 if match[2].lower() == "d" else 1)
        return (ahora or datetime.now(timezone.utc)) - timedelta(hours=horas)
    return parse_timestamp(value)


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


def event_from_dict(record: dict[str, Any], seleccion=None) -> Event | None:
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
    if seleccion is not None and not seleccion.previo(event_id):
        return None

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


def _open_text(path):
    raw = path.open("rb")
    bom = raw.read(4)
    raw.seek(0)
    encoding = "utf-16" if bom.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    return io.TextIOWrapper(raw, encoding=encoding, errors="replace")


def load_json(path: Path, warn: Warn, seleccion=None) -> Iterator[Event]:
    with _open_text(path) as stream:
        first = stream.read(4096).lstrip()
        stream.seek(0)
        if path.suffix.lower() == ".json" or first.startswith("["):
            if path.stat().st_size > 200 * 1024**2:
                warn(f"{path.name}: JSON de más de 200 MB; usa JSONL para lectura en streaming")
            try:
                parsed = json.load(stream)
            except json.JSONDecodeError:
                stream.seek(0)
            else:
                records = parsed if isinstance(parsed, list) else [parsed]
                for index, record in enumerate(records, 1):
                    try:
                        event = event_from_dict(record, seleccion)
                        if event is not None and (seleccion is None or seleccion.posterior(event)):
                            yield event
                    except ParseError as exc:
                        warn(f"{path.name}[{index}]: {exc}")
                return
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = event_from_dict(json.loads(line), seleccion)
                if event is not None and (seleccion is None or seleccion.posterior(event)):
                    yield event
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


def event_from_xml(element: ET.Element, seleccion=None) -> Event | None:
    """Convierte un nodo <Event> (sin namespaces) en Event."""
    system = element.find("System")
    if system is None:
        raise ParseError("evento sin nodo <System>")
    event_id = (system.findtext("EventID") or "").strip()
    created = system.find("TimeCreated")
    if not event_id or created is None or not created.get("SystemTime"):
        raise ParseError("falta EventID o TimeCreated")
    provider = system.find("Provider")
    try:
        numeric_id = int(event_id)
    except ValueError as exc:
        raise ParseError(f"EventID no numérico: {event_id!r}") from exc
    if seleccion is not None and not seleccion.previo(numeric_id):
        return None

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
        record_id = int(system.findtext("EventRecordID") or "0")
    except ValueError:
        record_id = 0  # Un ID de ordenación dañado no invalida la detección.
    return Event(
        timestamp=parse_timestamp(created.get("SystemTime")),
        event_id=numeric_id,
        computer=(system.findtext("Computer") or "").strip(),
        channel=(system.findtext("Channel") or "").strip(),
        provider=provider.get("Name", "") if provider is not None else "",
        data=data,
        _record_id=record_id,
    )


def _contiene_doctype(chunks):
    cola = ""
    for chunk in chunks:
        if "<!DOCTYPE" in (cola + chunk).upper():
            return True
        cola = (cola + chunk)[-16:]
    return False


def load_xml(path: Path, warn: Warn, seleccion=None) -> Iterator[Event]:
    # Primera pasada acotada: ningún evento sale de un documento con DTD,
    # aunque el atacante esconda la declaración tras muchos megabytes.
    with _open_text(path) as stream:
        if _contiene_doctype(iter(lambda: stream.read(65536), "")):
            warn(f"{path.name}: se rechaza XML con DOCTYPE (posible ataque de entidades)")
            return
        stream.seek(0)
        yield from _events_from_xml_chunks(iter(lambda: stream.read(65536), ""), path, warn, seleccion)


def _events_from_xml_text(text: str, path: Path, warn: Warn, seleccion=None) -> Iterator[Event]:
    if _contiene_doctype([text]):
        warn(f"{path.name}: se rechaza XML con DOCTYPE (posible ataque de entidades)")
        return
    yield from _events_from_xml_chunks((text[i:i+65536] for i in range(0, len(text), 65536)), path, warn, seleccion)


def _events_from_xml_chunks(chunks, path, warn, seleccion=None):
    """Consume fragmentos y retira cada Event de su padre tras normalizarlo."""
    parser = ET.XMLPullParser(events=("start", "end"))
    parser.feed("<WlhRoot>")
    stack = []
    pendiente = ""
    cola = ""
    index = 0

    def drenar():
        nonlocal index
        for action, element in parser.read_events():
            if action == "start":
                stack.append(element)
            else:
                if element.tag.rsplit("}", 1)[-1] == "Event":
                    index += 1
                    try:
                        _strip_namespaces(element)
                        event = event_from_xml(element, seleccion)
                        if event is not None and (seleccion is None or seleccion.posterior(event)):
                            yield event
                    except ParseError as exc:
                        warn(f"{path.name}[evento {index}]: {exc}")
                    finally:
                        element.clear()
                        if len(stack) > 1:
                            stack[-2].remove(element)
                stack.pop()
    try:
        for chunk in chunks:
            if "<!DOCTYPE" in (cola + chunk).upper():
                warn(f"{path.name}: se rechaza XML con DOCTYPE (posible ataque de entidades)")
                return
            cola = (cola + chunk)[-16:]
            pendiente += chunk
            # Las declaraciones XML pueden atravesar el límite de un fragmento.
            while "<?xml" in pendiente:
                start = pendiente.index("<?xml")
                end = pendiente.find("?>", start)
                if end == -1:
                    break
                pendiente = pendiente[:start] + pendiente[end+2:]
            cut = pendiente.rfind("<")
            if cut == -1:
                cut = len(pendiente)
            body, pendiente = pendiente[:cut], pendiente[cut:]
            parser.feed(body)
            yield from drenar()
        parser.feed(pendiente + "</WlhRoot>")
        yield from drenar()
        parser.close()
    except ET.ParseError as exc:
        warn(f"{path.name}: XML inválido ({exc})")


# Medido con wevtutil en Windows: 23 igualdades funcionan; 24 dan 15001.
# Cada cota temporal ocupa una comparación del mismo presupuesto.
XPATH_COMPARACIONES = 23


def consultas_xpath(ids=None, desde=None, hasta=None, rango=None):
    """Trocea la unión en consultas disjuntas dentro del límite nativo medido."""
    condiciones = []
    if desde:
        fecha = desde.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        condiciones.append(f"TimeCreated[@SystemTime>='{fecha}']")
    if hasta:
        fecha = hasta.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        condiciones.append(f"TimeCreated[@SystemTime<='{fecha}']")
    if rango:
        condiciones.extend((f"EventRecordID>={rango[0]}", f"EventRecordID<{rango[1]}"))
    budget = XPATH_COMPARACIONES - len(condiciones)
    valores = sorted(ids) if ids is not None else None
    bloques = [None] if valores is None else [valores[i:i+budget] for i in range(0, len(valores), budget)]
    for bloque in bloques:
        terms = condiciones[:]
        if bloque:
            terms.insert(0, "(" + " or ".join(f"EventID={i}" for i in bloque) + ")")
        yield "*[System[" + " and ".join(terms) + "]]" if terms else "*"


class ErrorConsulta(OSError):
    """wevtutil no pudo abrir o completar la consulta."""


def informacion_evtx(path):
    """Metadatos nativos, sin enumerar los eventos."""
    proc = subprocess.run(["wevtutil", "gli", str(path.resolve()), "/lf:true"], capture_output=True)
    if proc.returncode:
        return {}
    result = {}
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        key, sep, value = line.partition(":")
        if sep and value.strip().isdigit():
            result[key] = int(value.strip())
    return result


def consulta_estructurada(path, queries):
    """Une Select disjuntos; file:// usa la ruta Windows sin codificación URI."""
    route = "file://" + str(path.resolve())
    root = ET.Element("QueryList")
    query = ET.SubElement(root, "Query", Id="0", Path=route)
    for xpath in queries:
        ET.SubElement(query, "Select", Path=route).text = xpath
    # wevtutil interpreta rutas con tildes como ANSI si el UTF-8 carece de BOM.
    return codecs.BOM_UTF8 + ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _wevtutil_chunks(path, query):
    temporal = None
    if isinstance(query, (list, tuple)):
        # Cerrar antes de abrirlo desde wevtutil: Windows no comparte NamedTemporaryFile.
        with tempfile.NamedTemporaryFile(prefix="wlh-consulta-", suffix=".xml", delete=False) as stream:
            temporal = Path(stream.name)
            stream.write(consulta_estructurada(path, query))
        command = ["wevtutil", "qe", str(temporal), "/sq:true", "/f:xml", "/uni:true"]
    else:
        command = ["wevtutil", "qe", str(path.resolve()), "/lf:true", "/f:xml", "/uni:true", "/q:" + query]
    try:
        yield from _leer_wevtutil(command)
    finally:
        if temporal is not None:
            temporal.unlink(missing_ok=True)


def _leer_wevtutil(command):
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        # /uni:true fija UTF-16LE y evita adivinar ANSI frente a UTF-8.
        decoder = codecs.getincrementaldecoder("utf-16-le")(errors="strict")
        primero = True
        while True:
            raw = proc.stdout.read(65536)
            if not raw:
                break
            text = decoder.decode(raw)
            if primero:
                text = text.lstrip("\ufeff")
                primero = False
            yield text
        yield decoder.decode(b"", final=True)
        error = proc.stderr.read()
        if proc.wait() != 0:
            raise ErrorConsulta(f"código {proc.returncode}: " + error.decode("utf-16-le", errors="replace").strip())
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()


def load_evtx(path: Path, warn: Warn, seleccion=None) -> Iterator[Event]:
    if os.name == "nt" and shutil.which("wevtutil") is not None:
        ids = seleccion.plan.ids if seleccion and seleccion.plan is not None else None
        queries = list(consultas_xpath(ids, seleccion.desde if seleccion else None,
                                       seleccion.hasta if seleccion else None))
        emitidos = 0
        try:
            if queries:
                # El motor estructurado de Windows rechaza '&' incluso escapado
                # en Path. La lectura completa también hace una sola pasada.
                query = "*" if "&" in str(path) else queries[0] if len(queries) == 1 else queries
                for event in _events_from_xml_chunks(_wevtutil_chunks(path, query), path, warn, seleccion):
                    emitidos += 1
                    yield event
        except OSError as exc:
            if emitidos:
                # Una lectura parcial no se repite: duplicaría correlaciones.
                warn(f"{path.name}: error de wevtutil tras {emitidos} eventos ({exc})")
                return
            warn(f"{path.name}: XPath nativa rechazada; filtro en Python ({exc})")
            if seleccion is not None:
                seleccion.leidos = seleccion.descartados = 0
            try:
                yield from _events_from_xml_chunks(_wevtutil_chunks(path, "*"), path, warn, seleccion)
            except OSError as fallback_error:
                warn(f"{path.name}: error de wevtutil ({fallback_error})")
                return
        if seleccion is not None and (seleccion.estadisticas or seleccion.progreso):
            total = informacion_evtx(path).get("numberOfLogRecords")
            if total is not None and total >= seleccion.leidos:
                seleccion.descartados += total - seleccion.leidos
                seleccion.leidos = total
        return
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        warn(f"{path.name}: instala 'python-evtx' o exporta el log con wevtutil a XML")
        return
    with Evtx(str(path)) as log:
        for index, record in enumerate(log.records(), 1):
            try:
                text = record.xml()
                if "<!DOCTYPE" in text.upper():
                    raise ParseError("se rechaza XML con DOCTYPE")
                element = ET.fromstring(text)
                _strip_namespaces(element)
                event = event_from_xml(element, seleccion)
                if event is not None and (seleccion is None or seleccion.posterior(event)):
                    yield event
                element.clear()
            except Exception as exc:
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


def _cargar_fichero(path, seleccion):
    inicio = time.perf_counter()
    result = LoadResult(files=1)
    loader = _LOADERS.get(path.suffix.lower(), load_json)
    result.events.extend(loader(path, result.warnings.append, seleccion))
    if path.suffix.lower() == ".evtx":
        result.events.sort(key=lambda e: (e.timestamp, e._record_id))
    result.leidos = seleccion.leidos
    result.descartados = seleccion.descartados
    result.segundos = time.perf_counter() - inicio
    return result


def load_events(paths: Iterable[Path], *, plan=None, procesos=1, desde=None, hasta=None,
                progreso=False, estadisticas=False) -> LoadResult:
    """Carga eventos filtrados; conserva la lectura completa si no se pasa plan.

    La API histórica sigue siendo secuencial. La CLI elige os.cpu_count().
    Solo se crean tantos workers como ficheros; un fichero no paga el IPC.
    Con estadisticas o progreso, leidos incluye en EVTX los descartados nativos
    (gli). Sin ellos cuenta solo los examinados por Python y evita ese proceso.
    """
    if procesos < 1:
        raise ValueError("procesos debe ser al menos 1")
    if desde and hasta and desde > hasta:
        raise ValueError("--desde no puede ser posterior a --hasta")
    inicio = time.perf_counter()
    result = LoadResult()
    files = list(iter_files(paths))
    def incorporar(path, parte):
        result.files += parte.files
        result.events.extend(parte.events)
        result.warnings.extend(parte.warnings)
        result.leidos += parte.leidos
        result.descartados += parte.descartados
        if progreso:
            elapsed = time.perf_counter() - inicio
            print(f"{result.files}/{len(files)} ficheros · {path.name} · "
                  f"{result.leidos} eventos leídos · {len(result.events)} útiles · "
                  f"{result.leidos / max(elapsed, .000001):.0f} ev/s", file=sys.stderr)

    workers = min(procesos, len(files), 61 if os.name == "nt" else procesos)
    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            # Se consume en orden de entrada para que los empates temporales sean
            # idénticos a --procesos 1 y no dependan de quién termina primero.
            pendientes = []
            for offset in range(0, len(files), workers):
                lote = files[offset:offset+workers]
                pendientes = [pool.submit(_cargar_fichero, path, Seleccion(plan, desde, hasta, progreso=progreso, estadisticas=estadisticas)) for path in lote]
                for path, futuro in zip(lote, pendientes):
                    incorporar(path, futuro.result())
    else:
        for path in files:
            incorporar(path, _cargar_fichero(path, Seleccion(plan, desde, hasta, progreso=progreso, estadisticas=estadisticas)))
    result.events.sort(key=lambda e: e.timestamp)
    result.segundos = time.perf_counter() - inicio
    return result
