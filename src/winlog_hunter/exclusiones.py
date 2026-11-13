"""Validación y aplicación de exclusiones justificadas de hallazgos."""

from __future__ import annotations

import codecs
import json
import locale
import os
import warnings
from dataclasses import dataclass, field
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path

from .models import Finding, SEVERITY_ORDER
from .rules import RULES


PLANTILLA = {"version": 1, "exclusiones": [{
    "motivo": "Tarea legítima del antivirus corporativo", "reglas": ["WLH-007"],
    "equipos": ["PC-*"], "campos": {"tarea": "\\Antivirus\\*"}, "caduca": "2027-06-30",
}]}


def ruta_predeterminada() -> Path:
    """Ruta compartida por el usuario y las tareas ejecutadas como SYSTEM."""
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "winlog-hunter" / "exclusiones.json"


def resolver(path=None, sin_exclusiones=False, predeterminada=None) -> list[Exclusion]:
    """Carga la ruta explícita o la predeterminada si existe; permite inyectarla."""
    if sin_exclusiones:
        return []
    if path is not None:
        return cargar(path)
    candidate = Path(predeterminada) if predeterminada is not None else ruta_predeterminada()
    return cargar(candidate) if candidate.exists() else []


@dataclass(frozen=True)
class Exclusion:
    """Criterios de una exclusión validada; una lista expresa alternativas."""

    motivo: str
    reglas: tuple[str, ...] = ()
    equipos: tuple[str, ...] = ()
    campos: dict[str, str] = field(default_factory=dict)
    texto: str = ""
    severidad_maxima: str | None = None
    caduca: date | None = None


def cargar(path) -> list[Exclusion]:
    """Lee JSON y rechaza claves, tipos y criterios inválidos con su ubicación."""
    class Objeto(dict):
        """Conserva claves duplicadas hasta conocer su ruta en el documento."""

        def __init__(self, pares):
            super().__init__()
            self.duplicadas = []
            for clave, valor in pares:
                if clave in self:
                    self.duplicadas.append(clave)
                self[clave] = valor

    def error(ruta, mensaje):
        raise ValueError(f"{ruta}: {mensaje}")

    def objeto(valor, ruta, claves):
        if not isinstance(valor, dict):
            error(ruta, "debe ser un objeto")
        if isinstance(valor, Objeto) and valor.duplicadas:
            error(f"{ruta}.{valor.duplicadas[0]}", "clave duplicada")
        for clave in valor:
            if clave not in claves:
                error(f"{ruta}.{clave}", "clave desconocida")

    def cadena(valor, ruta):
        if not isinstance(valor, str) or not valor.strip():
            error(ruta, "debe ser un texto no vacío")

    try:
        data = json.loads(_leer_texto(Path(path)), object_pairs_hook=Objeto)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: no se pudieron leer las exclusiones: {exc}") from exc
    objeto(data, "documento", {"version", "exclusiones"})
    if type(data.get("version")) is not int or data["version"] != 1:
        error("version", "debe ser 1")
    if not isinstance(data.get("exclusiones"), list):
        error("exclusiones", "debe ser una lista")
    resultado = []
    conocidas = {r.id for r in RULES}
    criterios = {"reglas", "equipos", "campos", "texto", "severidad_maxima", "caduca"}
    for i, item in enumerate(data["exclusiones"]):
        ruta = f"exclusiones[{i}]"
        objeto(item, ruta, criterios | {"motivo"})
        cadena(item.get("motivo"), ruta + ".motivo")
        if not criterios.intersection(item):
            error(ruta, "debe contener al menos un criterio")
        for clave in ("reglas", "equipos"):
            if clave in item:
                if not isinstance(item[clave], list) or not item[clave]:
                    error(ruta + "." + clave, "debe ser una lista no vacía")
                for j, valor in enumerate(item[clave]):
                    cadena(valor, f"{ruta}.{clave}[{j}]")
                    if clave == "reglas" and valor != "*" and valor not in conocidas:
                        error(f"{ruta}.reglas[{j}]", "regla inexistente")
        if "campos" in item:
            objeto(item["campos"], ruta + ".campos", set(item["campos"]) if isinstance(item["campos"], dict) else set())
            if not item["campos"]:
                error(ruta + ".campos", "debe contener al menos un campo")
            for clave, valor in item["campos"].items():
                cadena(clave, ruta + ".campos")
                cadena(valor, ruta + ".campos." + clave)
        if "texto" in item:
            cadena(item["texto"], ruta + ".texto")
        if "severidad_maxima" in item:
            if not isinstance(item["severidad_maxima"], str) or item["severidad_maxima"] not in SEVERITY_ORDER:
                error(ruta + ".severidad_maxima", "severidad desconocida")
        valores = dict(item)
        for clave in ("reglas", "equipos"):
            if clave in valores:
                valores[clave] = tuple(valores[clave])
        if "caduca" in item:
            valor = item["caduca"]
            try:
                fecha = date.fromisoformat(valor)
                if fecha.isoformat() != valor:
                    raise ValueError()
            except (TypeError, ValueError):
                error(ruta + ".caduca", "debe ser una fecha ISO AAAA-MM-DD válida")
            valores["caduca"] = fecha
        resultado.append(Exclusion(**valores))
    return resultado


def _leer_texto(path: Path) -> str:
    """UTF-8 (con o sin BOM), UTF-16 con BOM (PowerShell 5.1 con `>`) o la codificación local."""
    datos = path.read_bytes()
    if datos.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return datos.decode("utf-16")
    try:
        return datos.decode("utf-8-sig")
    except UnicodeDecodeError:
        return datos.decode(locale.getpreferredencoding(False))


def _valores(valor):
    if isinstance(valor, dict):
        for elemento in valor.values():
            yield from _valores(elemento)
    elif isinstance(valor, (list, tuple)):
        for elemento in valor:
            yield from _valores(elemento)
    else:
        yield str(valor)


def aplicar(findings: list[Finding], exclusiones: list[Exclusion], hoy: date) -> tuple[list[Finding], list[dict]]:
    """Devuelve visibles y registros excluidos; gana la primera coincidencia."""
    activas = []
    for exclusion in exclusiones:
        if exclusion.caduca and exclusion.caduca < hoy:
            warnings.warn(f"Exclusión caducada ({exclusion.caduca}): {exclusion.motivo}", UserWarning)
        else:
            activas.append(exclusion)
    visibles, excluidos = [], []
    def coincide(valor, patron):
        return fnmatchcase(str(valor).casefold(), patron.casefold())
    for finding in findings:
        for e in activas:
            if e.reglas and "*" not in e.reglas and finding.rule_id not in e.reglas:
                continue
            if e.equipos and not any(coincide(c, p) for c in finding.computers for p in e.equipos):
                continue
            if e.campos and not all(k in finding.evidence and any(coincide(v, p) for v in _valores(finding.evidence[k])) for k, p in e.campos.items()):
                continue
            if e.texto and not any(e.texto.casefold() in v.casefold() for v in [finding.summary, *_valores(finding.evidence)]):
                continue
            if e.severidad_maxima and finding.rank > SEVERITY_ORDER[e.severidad_maxima]:
                continue
            excluidos.append({"rule_id": finding.rule_id, "summary": finding.summary,
                              "veces": finding.veces, "motivo": e.motivo})
            break
        else:
            visibles.append(finding)
    return visibles, excluidos


def aplicar_con_avisos(findings, exclusiones, hoy, avisos):
    """Conserva los avisos de caducidad en todos los informes."""
    with warnings.catch_warnings(record=True) as capturados:
        warnings.simplefilter("always", UserWarning)
        resultado = aplicar(findings, exclusiones, hoy)
    avisos.extend(str(aviso.message) for aviso in capturados)
    return resultado
