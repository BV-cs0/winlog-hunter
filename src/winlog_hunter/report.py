"""Informes: consola, JSON, Markdown y HTML.

Los datos de los logs los controla potencialmente un atacante, así que:
  * en consola se eliminan caracteres de control (evita inyección de secuencias ANSI),
  * en Markdown se escapan los caracteres especiales,
  * en HTML todo pasa por html.escape y la página lleva una CSP que bloquea scripts.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .models import SEVERITY_ORDER, Finding

SEVERITY_LABEL = {"critical": "CRÍTICA", "high": "ALTA", "medium": "MEDIA", "low": "BAJA"}
_DESCENDING = sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get, reverse=True)

_ANSI = {"critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[1;93m", "low": "\033[1;94m"}
_BOLD, _DIM, _RESET = "\033[1m", "\033[2m", "\033[0m"
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


@dataclass
class Stats:
    events: int
    files: int
    first_event: datetime | None = None
    last_event: datetime | None = None
    warnings: list[str] = field(default_factory=list)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in _DESCENDING}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _label(key: str) -> str:
    text = key.replace("_", " ")
    return text[:1].upper() + text[1:]


def _value(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value)
    return str(value)


def _clean(text: str) -> str:
    """Quita caracteres de control (incluido ESC) y aplana saltos de línea."""
    return _CONTROL.sub("", text.replace("\r", " ").replace("\n", " ").replace("\t", " "))


# --------------------------------------------------------------------------- #
# Consola
# --------------------------------------------------------------------------- #


def render_console(findings: list[Finding], stats: Stats, color: bool = False) -> str:
    def paint(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines = [f"{paint(_BOLD, 'winlog-hunter')} {__version__} · {stats.events} eventos en {stats.files} fichero(s)"]
    if stats.first_event and stats.last_event:
        lines.append(f"Periodo: {fmt_ts(stats.first_event)} a {fmt_ts(stats.last_event)}")
    counts = severity_counts(findings)
    lines.append(
        f"Hallazgos: {len(findings)}  ("
        + " · ".join(f"{SEVERITY_LABEL[s].lower()} {n}" for s, n in counts.items())
        + ")"
    )
    if not findings:
        lines.append("")
        lines.append("Sin hallazgos con los filtros actuales.")

    for f in findings:
        lines.append("")
        lines.append(f"{paint(_ANSI[f.severity], f'[{SEVERITY_LABEL[f.severity]}]')} {paint(_BOLD, f.rule_id)} {f.title}")
        meta = (
            f"{fmt_ts(f.first_seen)} · {_clean(', '.join(f.computers)) or '?'} · "
            f"MITRE {', '.join(f.mitre)} · {f.event_count} evento(s)"
        )
        lines.append("    " + paint(_DIM, meta))
        lines.append("    " + _clean(f.summary))
        for key, value in f.evidence.items():
            text = _clean(_value(value))
            if len(text) > 220:
                text = text[:219] + "…"
            lines.append(f"      {_label(key)}: {text}")

    if stats.warnings:
        lines.append("")
        lines.append(paint(_DIM, f"Avisos de lectura: {len(stats.warnings)}"))
        for warning in stats.warnings[:5]:
            lines.append(paint(_DIM, f"  - {_clean(warning)}"))
        if len(stats.warnings) > 5:
            lines.append(paint(_DIM, f"  ... y {len(stats.warnings) - 5} más"))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def render_json(findings: list[Finding], stats: Stats) -> str:
    document = {
        "tool": "winlog-hunter",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "events": stats.events,
            "files": stats.files,
            "first_event": stats.first_event.isoformat() if stats.first_event else None,
            "last_event": stats.last_event.isoformat() if stats.last_event else None,
            "warnings": stats.warnings,
            "findings_by_severity": severity_counts(findings),
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(document, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>|#~])")


def _md(text: Any) -> str:
    return _MD_SPECIAL.sub(r"\\\1", _clean(_value(text)))


def render_markdown(findings: list[Finding], stats: Stats) -> str:
    counts = severity_counts(findings)
    out = [
        "# Informe de winlog-hunter",
        "",
        f"- **Eventos analizados:** {stats.events} en {stats.files} fichero(s)",
    ]
    if stats.first_event and stats.last_event:
        out.append(f"- **Periodo:** {fmt_ts(stats.first_event)} a {fmt_ts(stats.last_event)}")
    out.append(f"- **Generado:** {fmt_ts(datetime.now(timezone.utc))} con winlog-hunter {__version__}")
    out += ["", "| Severidad | Hallazgos |", "|---|---|"]
    out += [f"| {SEVERITY_LABEL[s]} | {n} |" for s, n in counts.items()]
    out += ["", "## Resumen", "", "| # | Severidad | Regla | Hallazgo | Equipo | Primera vez |", "|---|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        out.append(
            f"| {i} | {SEVERITY_LABEL[f.severity]} | {f.rule_id} | {_md(f.summary)} | "
            f"{_md(', '.join(f.computers)) or '?'} | {fmt_ts(f.first_seen)} |"
        )
    out += ["", "## Detalle"]
    for i, f in enumerate(findings, 1):
        out += [
            "",
            f"### {i}. [{SEVERITY_LABEL[f.severity]}] {f.rule_id} · {_md(f.title)}",
            "",
            _md(f.summary),
            "",
            f"- **MITRE ATT&CK:** {', '.join(f.mitre)}",
            f"- **Ventana:** {fmt_ts(f.first_seen)} a {fmt_ts(f.last_seen)} ({f.event_count} evento(s))",
        ]
        out += [f"- **{_label(k)}:** {_md(v)}" for k, v in f.evidence.items()]
    if stats.warnings:
        out += ["", "## Avisos de lectura", ""] + [f"- {_md(w)}" for w in stats.warnings]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

_HTML_TEMPLATE = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Informe winlog-hunter</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5b6475;--border:#dde1e8;
--critical:#b4232c;--high:#d1501f;--medium:#a77a00;--low:#2f6fb5;--code:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#11151c;--card:#1a2029;--text:#e6e9ef;--muted:#9aa3b2;
--border:#2c3440;--critical:#ff6b72;--high:#ff8f5a;--medium:#f2c94c;--low:#6fa8ff;--code:#232a35}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px}
h1{font-size:26px;margin:0 0 4px}
.meta{color:var(--muted);margin:0 0 24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:28px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.card b{display:block;font-size:28px;line-height:1.1}
.card span{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.04em}
.finding{background:var(--card);border:1px solid var(--border);border-left:5px solid var(--sev);
border-radius:10px;padding:16px 18px;margin-bottom:14px}
.finding p,.finding h2{overflow-wrap:anywhere}
.finding h2{font-size:17px;margin:0 0 6px}
.badge{display:inline-block;font-size:12px;font-weight:700;color:var(--sev);border:1px solid var(--sev);
border-radius:999px;padding:1px 9px;margin-right:6px;vertical-align:2px}
.sub{color:var(--muted);font-size:13px;margin:0 0 10px}
dl{display:grid;grid-template-columns:minmax(120px,190px) 1fr;gap:4px 14px;margin:10px 0 0}
dt{color:var(--muted)}
dd{margin:0;overflow-wrap:anywhere}
code{background:var(--code);border-radius:4px;padding:1px 5px;font:13px/1.45 ui-monospace,Consolas,monospace}
.empty{color:var(--muted)}
footer{color:var(--muted);font-size:13px;margin-top:28px}
@media (max-width:560px){dl{grid-template-columns:1fr}dt{margin-top:6px}}
</style>
</head>
<body>
<main>
{{BODY}}
</main>
</body>
</html>
"""

_CODE_KEYS = {
    "línea_de_comandos", "comando_decodificado", "ruta", "acción", "proceso_padre", "proceso_hijo",
    "proceso", "proceso_origen", "clave", "valor", "consulta", "fragmento",
}


def render_html(findings: list[Finding], stats: Stats) -> str:
    esc = html.escape
    counts = severity_counts(findings)
    parts = ["<h1>Informe de winlog-hunter</h1>"]
    period = ""
    if stats.first_event and stats.last_event:
        period = f" · {esc(fmt_ts(stats.first_event))} a {esc(fmt_ts(stats.last_event))}"
    parts.append(f'<p class="meta">{stats.events} eventos en {stats.files} fichero(s){period}</p>')

    parts.append('<section class="cards">')
    parts.append(f'<div class="card"><b>{len(findings)}</b><span>Hallazgos</span></div>')
    for sev, n in counts.items():
        parts.append(f'<div class="card" style="color:var(--{sev})"><b>{n}</b><span>{SEVERITY_LABEL[sev]}</span></div>')
    parts.append("</section>")

    if not findings:
        parts.append('<p class="empty">Sin hallazgos con los filtros actuales.</p>')
    for f in findings:
        parts.append(f'<article class="finding" style="--sev:var(--{f.severity})">')
        parts.append(
            f'<h2><span class="badge">{SEVERITY_LABEL[f.severity]}</span>{esc(f.rule_id)} · {esc(f.title)}</h2>'
        )
        parts.append(
            f'<p class="sub">{esc(fmt_ts(f.first_seen))} · {esc(", ".join(f.computers) or "?")} · '
            f'MITRE {esc(", ".join(f.mitre))} · {f.event_count} evento(s)</p>'
        )
        parts.append(f"<p>{esc(f.summary)}</p><dl>")
        for key, value in f.evidence.items():
            text = esc(_value(value))
            if key in _CODE_KEYS:
                text = f"<code>{text}</code>"
            parts.append(f"<dt>{esc(_label(key))}</dt><dd>{text}</dd>")
        parts.append("</dl></article>")

    if stats.warnings:
        parts.append(f"<h2>Avisos de lectura ({len(stats.warnings)})</h2><ul>")
        parts += [f"<li>{esc(w)}</li>" for w in stats.warnings[:100]]
        parts.append("</ul>")
    parts.append(f"<footer>Generado el {esc(fmt_ts(datetime.now(timezone.utc)))} con winlog-hunter {__version__}</footer>")
    return _HTML_TEMPLATE.replace("{{BODY}}", "\n".join(parts))


RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
}
