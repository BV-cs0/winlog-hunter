"""Reglas de descubrimiento."""

from __future__ import annotations

import re
import ipaddress
from collections import defaultdict

from .base import (Config, Event, Hit, Iterator, UNKNOWN, _bursts, _exe, _is_system_account,
                   _maintenance_process, _processes, _truncate, _windows_path, rule)


_ENUM_PIPES = {"srvsvc", "samr", "lsarpc", "winreg", "wkssvc"}


@rule("WLH-035", "Reconocimiento de cuentas, grupos y equipos", "medium", ["T1087", "T1069", "T1135", "T1018"],
      "Consultas de grupos por procesos no habituales, enumeración RPC de varios canales y ráfagas de comandos de dominio.")
def reconnaissance(events: list[Event], cfg: Config) -> Iterator[Hit]:
    pipes: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    queries: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.channel.lower() != "security" and "security-auditing" not in e.provider.lower():
            continue
        if e.event_id in (4798, 4799):
            image = e.get("CallerProcessName", "ProcessName")
            if not image or _maintenance_process(image) or (_windows_path(image) and _exe(image) in {"mmc.exe", "svchost.exe", "lsass.exe", "services.exe"}):
                continue
            if re.fullmatch(r"[a-z]:\\windows\\(?:syswow64\\)?explorer\.exe", image, re.I):
                continue
            queries[(e.computer.lower(), image)].append(e)
        elif e.event_id == 4661 and (e.get("ObjectType").upper() == "SAM_GROUP" or e.get("ObjectName").lower() in {"domain admins", "admins. del dominio"} or re.search(r"S-1-5-21-(?:\d+-){3}512$", e.get("ObjectName"), re.I)):
            yield Hit([e], f"Consulta a un grupo SAM en {e.computer or UNKNOWN}",
                      {"usuario": e.get("SubjectUserName"), "objeto": e.get("ObjectName"), "proceso": e.get("ProcessName")}, severity="low")
        elif e.event_id == 5145 and e.get("ShareName").lower().endswith("ipc$"):
            pipe = e.get("RelativeTargetName").lower().strip("\\")
            ip = e.get("IpAddress")
            try:
                address = ipaddress.ip_address(ip)
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                    address = address.ipv4_mapped
                local = address.is_loopback or address.is_unspecified
            except ValueError:
                local = True
            if pipe in _ENUM_PIPES and not local and not _is_system_account(e.get("SubjectUserName")):
                pipes[(e.computer.lower(), ip, e.get("SubjectUserName").lower())].append(e)
    for (_, image), evs in queries.items():
        for burst in _bursts(evs, cfg.window, 1):
            targets = sorted({x.get("TargetSid", "TargetUserName") for x in burst if x.get("TargetSid", "TargetUserName")})
            yield Hit(burst, f"{_exe(image)} consultó pertenencia a grupos en {burst[0].computer or UNKNOWN}",
                      {"proceso": image, "cuentas_o_grupos": targets}, severity="medium" if len(targets) >= 3 else "low")
    for (_, ip, _), evs in pipes.items():
        for burst in _bursts(evs, cfg.window, 3, distinct=lambda x: x.get("RelativeTargetName").lower()):
            yield Hit(burst, f"{ip} consultó varios canales RPC de enumeración", {"origen": ip,
                      "pipes": sorted({x.get("RelativeTargetName") for x in burst}), "usuario": burst[0].get("SubjectUserName")})
    commands: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for p in _processes(events):
        name, command = _exe(p.image), p.command_line
        if ((name in {"net.exe", "net1.exe"} and re.search(r"\b(?:user|group|localgroup)\b.* /domain\b", command, re.I)) or
            (name == "nltest.exe" and re.search(r"/(?:dclist|domain_trusts)\b", command, re.I)) or
            (name in {"dsquery.exe", "adfind.exe"} and command and not re.search(r"(?:^|\s)[-/](?:\?|help)\b", command, re.I))):
            commands[(p.event.computer.lower(), p.user.lower())].append(p.event)
    for evs in commands.values():
        for burst in _bursts(evs, cfg.window, 3, distinct=lambda x: x.get("CommandLine").lower()):
            yield Hit(burst, f"Ráfaga de comandos de reconocimiento en {burst[0].computer or UNKNOWN}",
                      {"comandos": [_truncate(x.get("CommandLine")) for x in burst[:10]], "usuario": burst[0].get("User", "SubjectUserName")})
