"""Reglas de evasión."""

from __future__ import annotations

import re
import ntpath

from .base import (Config, Event, Hit, Iterator, UNKNOWN, rule)
from .base import _exe, _is_sysmon, _processes, _truncate, _windows_path, decode_powershell


_ORIGINAL_NAMES = {
    "cmd.exe": {"cmd.exe"}, "powershell.exe": {"powershell.exe"},
    "pwsh.exe": {"pwsh.exe"}, "rundll32.exe": {"rundll32.exe"},
    "regsvr32.exe": {"regsvr32.exe"}, "certutil.exe": {"certutil.exe"},
    "mshta.exe": {"mshta.exe"}, "wmic.exe": {"wmic.exe"},
    # Los metadatos de Sysinternals conservan el nombre del fuente en algunas versiones.
    "psexec.c": {"psexec.exe", "psexec64.exe", "psexec64a.exe"},
    "psexec.exe": {"psexec.exe", "psexec64.exe", "psexec64a.exe"},
    "procdump": {"procdump.exe", "procdump64.exe", "procdump64a.exe"},
    "procdump.exe": {"procdump.exe", "procdump64.exe", "procdump64a.exe"},
}
_SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe", "smss.exe", "wermgr.exe"}
_ACCESSIBILITY = {"sethc.exe", "osk.exe", "utilman.exe", "magnify.exe", "narrator.exe"}


@rule("WLH-023", "Binario renombrado o disfrazado", "medium", ["T1036.003", "T1036.005"],
      "Nombre original de una utilidad conocida distinto del ejecutable, o proceso de sistema fuera de su ruta.")
def masquerading(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for p in _processes(events):
        name = _exe(p.image)
        if not name:
            continue
        original = _exe(p.event.get("OriginalFileName")) if _is_sysmon(p.event) else ""
        reason, severity, mitre = "", "medium", ["T1036.003"]
        if original in _ORIGINAL_NAMES and name not in _ORIGINAL_NAMES[original]:
            reason = "nombre distinto al OriginalFileName de una utilidad conocida"
            if name in _ACCESSIBILITY and original in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
                reason, severity = "binario de accesibilidad sustituido por una shell", "high"
        path = ntpath.normpath(p.image.strip('"')).lower()
        misplaced = name in _SYSTEM_NAMES and not _windows_path(path)
        misplaced |= name == "explorer.exe" and not bool(re.fullmatch(r"[a-z]:\\windows\\explorer\.exe", path)) and not _windows_path(path, ("syswow64", "winsxs"))
        if misplaced:
            reason, severity, mitre = "nombre de proceso de sistema fuera de su ruta", "high", ["T1036.005"]
        if reason:
            yield Hit([p.event], f"{name}: {reason} en {p.event.computer or UNKNOWN}",
                      {"indicador": reason, "proceso": p.image, "nombre_original": original,
                       "usuario": p.user, "línea_de_comandos": _truncate(p.command_line)},
                      severity=severity, mitre=mitre)


_COMMAND_TOKEN = re.compile(r'^\s*(?:"([^"]+)"|([^\s"]+))\s*(.*)$', re.S)


def _command_target(image: str, command: str) -> tuple[str, str]:
    """Identifica la utilidad invocada sin interpretar argumentos impresos por echo."""
    name = _exe(image)
    if name == "cmd.exe":
        match = re.search(r"(?:^|\s)/[ck]\s+(.+)$", command, re.I)
        if not match:
            return name, command
        nested = match.group(1).strip()
        if nested.startswith('""') and nested.endswith('"'):
            nested = nested[1:-1]
        token = _COMMAND_TOKEN.match(nested)
        if token:
            name = _exe(token.group(1) or token.group(2))
            return name if name.endswith(".exe") else name + ".exe", token.group(3)
    return name, command


@rule("WLH-025", "Evasión e inhibición de recuperación por comandos", "high",
      ["T1490", "T1562.001", "T1562.004", "T1564.001", "T1070"],
      "Borrado de copias, desactivación de auditoría o defensas, ocultación y parada de EventLog.")
def defense_commands(events: list[Event], cfg: Config) -> Iterator[Hit]:
    processes = list(_processes(events))
    for p in processes:
        name, text = _command_target(p.image, p.command_line)
        text = text.lower()
        reason, technique, severity = "", "T1562.001", "high"
        related, eventlog_command = [p.event], ""
        if (name == "vssadmin.exe" and re.search(r"\bdelete\s+shadows\b", text) or
            name == "wmic.exe" and re.search(r"\bshadowcopy\b.*\bdelete\b", text) or
            name == "wbadmin.exe" and re.search(r"\bdelete\s+(?:catalog|systemstatebackup|backup)\b", text) or
            name == "bcdedit.exe" and re.search(r"/set\b.*(?:\brecoveryenabled\s+no\b|\bbootstatuspolicy\s+ignore(?:all|boot|shutdown)?failures\b)", text)):
            reason, technique = "eliminación de copias o inhibición de recuperación", "T1490"
        elif name == "wevtutil.exe" and re.search(r"(?:^|\s)(?:cl|clear-log)\s+|(?:^|\s)(?:sl|set-log)\s+.* /e:false\b", text):
            reason, technique = "borrado o desactivación de un registro de eventos", "T1070.001"
        elif name == "auditpol.exe" and re.search(r"/(?:clear|remove)\b|/set\b.* /(?:success|failure):disable\b", text):
            reason = "desactivación de auditoría"
        elif name == "netsh.exe":
            if re.search(r"\badvfirewall\s+set\b.*\bstate\s+off\b", text):
                reason, technique = "desactivación del firewall", "T1562.004"
            elif re.search(r"\binterface\s+portproxy\s+add\b", text):
                reason, technique, severity = "redirección de puertos con netsh", "T1090", "medium"
        elif name in {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}:
            text += "\n" + decode_powershell(p.command_line).lower()
            if re.search(r"\bset-mppreference\b[^;\r\n]*-disable\w+\s+(?:\$true|1)\b", text):
                reason = "desactivación de protección de Defender"
            elif re.search(r"\badd-mppreference\b[^;\r\n]*-exclusion(?:path|process|extension)\b", text):
                reason, severity = "adición de una exclusión de Defender", "medium"
        elif name == "attrib.exe" and re.search(r"(?:^|\s)\+h(?:\s|$)", text) and re.search(r"(?:^|\s)\+s(?:\s|$)", text):
            reason, technique, severity = "fichero marcado como oculto y de sistema", "T1564.001", "medium"
        elif name in {"net.exe", "net1.exe"} and re.search(r'\bstop\s+"?eventlog\b', text):
            reason = "parada del servicio EventLog"
        elif name == "sc.exe" and re.search(r'\bconfig\s+"?eventlog"?\s+.*\bstart=\s*disabled\b', text):
            reason = "servicio EventLog deshabilitado"
        elif name == "taskkill.exe":
            if re.search(r"\bservices\s+eq\s+eventlog\b", text):
                reason = "terminación del proceso del servicio EventLog"
            else:
                pid = re.search(r"/pid\s+(\d+)\b", text)
                # El último inicio observado evita atribuir un PID reutilizado a EventLog.
                for prior in reversed(processes):
                    if not pid or prior.event.computer.lower() != p.event.computer.lower():
                        continue
                    if not (p.event.timestamp - cfg.window <= prior.event.timestamp <= p.event.timestamp):
                        continue
                    raw_pid = prior.event.get("ProcessId", "NewProcessId")
                    try:
                        prior_pid = int(raw_pid, 16 if raw_pid.lower().startswith("0x") else 10)
                    except ValueError:
                        continue
                    if prior_pid != int(pid.group(1)):
                        continue
                    if (_exe(prior.image) == "svchost.exe" and _windows_path(prior.image) and
                        re.search(r"(?:^|\s)-s\s+eventlog\b", prior.command_line, re.I)):
                        reason = "terminación del svchost identificado como EventLog"
                        related, eventlog_command = [prior.event, p.event], prior.command_line
                    break
        if reason:
            yield Hit(related, f"{reason.capitalize()} en {p.event.computer or UNKNOWN}",
                      {"indicador": reason, "proceso": p.image, "usuario": p.user,
                       "línea_de_comandos": _truncate(p.command_line),
                       "comando_de_eventlog": _truncate(eventlog_command)}, severity=severity, mitre=[technique])

@rule(
    "WLH-005",
    "Registro de eventos borrado",
    "critical",
    ["T1685.005"],
    "Se vació el registro de seguridad (1102) u otro registro (104): típico para borrar huellas.",
)
def log_cleared(events: list[Event], cfg: Config) -> Iterator[Hit]:
    for e in events:
        channel, provider = e.channel.lower(), e.provider.lower()
        is_security = e.event_id == 1102 and (channel in ("security", "") or "eventlog" in provider)
        is_other = e.event_id == 104 and (channel == "system" or "eventlog" in provider)
        if not (is_security or is_other):
            continue
        log = "Security" if is_security else (e.get("Channel") or UNKNOWN)
        who = e.get("SubjectUserName")
        yield Hit(
            [e],
            f"Se borró el registro '{log}' en {e.computer or UNKNOWN}" + (f" (usuario: {who})" if who else ""),
            {"registro": log, "usuario": who, "dominio": e.get("SubjectDomainName")},
        )


