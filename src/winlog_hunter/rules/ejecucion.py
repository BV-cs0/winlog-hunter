"""Reglas de ejecucion."""

from __future__ import annotations

from .base import (Config, ENCODED, Event, Hit, Iterator, UNKNOWN, _LOLBINS, _OFFICE, _POWERSHELL, _PS_INDICATORS, _SCRIPT_BLOCK_INDICATORS, _SHELLS, _exe, _processes, _truncate, decode_powershell, rule)

@rule(
    "WLH-010",
    "PowerShell sospechoso",
    "high",
    ["T1059.001"],
    "PowerShell con comando codificado, descarga + IEX o evasión de AMSI (alta); varias banderas de ocultación (media).",
)
def suspicious_powershell(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        if _exe(p.image) not in _POWERSHELL or not p.command_line:
            continue
        decoded = decode_powershell(p.command_line)
        text = f"{p.command_line}\n{decoded}"
        indicators = [name for name, regex in _PS_INDICATORS if regex.search(text)]
        if decoded:
            indicators.insert(0, ENCODED)
        strong = bool(decoded) or "evasión de AMSI" in indicators or (
            "descarga remota" in indicators and "ejecución dinámica (IEX)" in indicators
        )
        if not strong and len(indicators) < 2:
            continue
        yield Hit(
            [p.event],
            f"PowerShell sospechoso en {p.event.computer or UNKNOWN}: {', '.join(indicators)}",
            {
                "usuario": p.user,
                "proceso_padre": p.parent,
                "línea_de_comandos": _truncate(p.command_line),
                "comando_decodificado": _truncate(decoded),
                "indicadores": indicators,
            },
            severity="high" if strong else "medium",
        )


@rule(
    "WLH-011",
    "Uso malicioso de binario del sistema (LOLBin)",
    "high",
    ["T1218"],
    "certutil, mshta, rundll32, regsvr32, bitsadmin o wmic usados con argumentos típicos de ataque.",
)
def lolbins(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        exe = _exe(p.image)
        for name, pattern, mitre, technique in _LOLBINS:
            if exe == name and pattern.search(p.command_line):
                yield Hit(
                    [p.event],
                    f"{name} usado para {technique} en {p.event.computer or UNKNOWN}",
                    {
                        "binario": name,
                        "técnica": technique,
                        "usuario": p.user,
                        "proceso_padre": p.parent,
                        "línea_de_comandos": _truncate(p.command_line),
                    },
                    mitre=mitre,
                )
                break


@rule(
    "WLH-012",
    "Office lanzando una shell",
    "high",
    ["T1566.001", "T1204.002"],
    "Word, Excel, Outlook... abren cmd, PowerShell u otros intérpretes: patrón clásico de documento malicioso.",
)
def office_child_process(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        parent, child = _exe(p.parent), _exe(p.image)
        if parent in _OFFICE and child in _SHELLS:
            yield Hit(
                [p.event],
                f"{parent} lanzó {child} en {p.event.computer or UNKNOWN}",
                {
                    "proceso_padre": p.parent,
                    "proceso_hijo": p.image,
                    "usuario": p.user,
                    "línea_de_comandos": _truncate(p.command_line),
                },
            )


@rule(
    "WLH-021",
    "Script de PowerShell malicioso",
    "high",
    ["T1059.001"],
    "Evento 4104 (Script Block Logging): el código ejecutado contiene volcado de LSASS, Mimikatz, evasión de AMSI, inyección...",
)
def malicious_script_block(events: list[Event], cfg: Config) -> Iterator[Hit]:
    seen: set[str] = set()
    for e in events:
        text = e.get("ScriptBlockText") if e.event_id == 4104 else ""
        found = [(name, mitre) for name, regex, mitre in _SCRIPT_BLOCK_INDICATORS if text and regex.search(text)]
        block = e.get("ScriptBlockId") or text[:200]
        if not found or block in seen:
            continue
        seen.add(block)
        yield Hit(
            [e],
            f"Script de PowerShell con {', '.join(n for n, _ in found)} en {e.computer or UNKNOWN}",
            {
                "indicadores": [n for n, _ in found],
                "ruta": e.get("Path"),
                "fragmento": _truncate(text, 400),
            },
            mitre=sorted({"T1059.001", *(m for _, m in found)}),
            severity="critical" if any(m.startswith("T1003") for _, m in found) else None,
        )


