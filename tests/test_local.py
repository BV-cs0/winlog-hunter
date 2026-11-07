import json
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from helpers import SAMPLE

from winlog_hunter import local

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def fake_exporter(hours, folder):
    target = folder / "Security.jsonl"
    shutil.copy(SAMPLE, target)
    return local.Export([target], ["Exportado Security", "Omitido Sysmon: no existe en este equipo"])


class ThisComputer(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.out, True)

    def test_writes_reports_journal_and_alerts(self):
        shown, lines = [], []
        result = local.analyze_this_computer(
            output=self.out, exporter=fake_exporter, notifier=shown.append, log=lines.append
        )
        self.assertTrue(result.html.exists() and result.json.exists())
        data = json.loads(result.json.read_text(encoding="utf-8"))
        self.assertEqual(data["stats"]["events"], result.events)
        self.assertEqual(result.counts["critical"], 3)
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(len(shown), 1)
        self.assertIn("3 hallazgo(s) importantes", shown[0])
        journal = (self.out / "ejecuciones.log").read_text(encoding="utf-8")
        self.assertIn("Exportado Security", journal)
        self.assertIn("Aviso mostrado en pantalla", journal)

    def test_no_alert_when_disabled_or_below_threshold(self):
        shown = []
        local.analyze_this_computer(output=self.out, exporter=fake_exporter, notifier=shown.append,
                                    notify_from=None, log=lambda m: None)
        self.assertEqual(shown, [])

    def test_fails_cleanly_when_nothing_exported(self):
        with self.assertRaises(local.LocalError):
            local.analyze_this_computer(output=self.out, exporter=lambda h, f: local.Export([], ["Omitido todo"]),
                                        log=lambda m: None)


class ScheduledTask(unittest.TestCase):
    def test_task_xml_runs_the_module_as_system(self):
        xml = local.task_xml("21:30", 48, Path(r"C:\Users\Ana\Documents\winlog-hunter"), "high",
                             python=r"C:\Python\python.exe")
        root = ET.fromstring(xml.split("\n", 1)[1])
        exe = root.find("t:Actions/t:Exec/t:Command", NS).text
        args = root.find("t:Actions/t:Exec/t:Arguments", NS).text
        self.assertTrue(exe.lower().endswith("python.exe"))
        self.assertEqual(
            args,
            r'-m winlog_hunter equipo --horas 48 --salida "C:\Users\Ana\Documents\winlog-hunter" '
            r"--avisar-desde high --sin-abrir",
        )
        self.assertEqual(root.find("t:Principals/t:Principal/t:UserId", NS).text, "S-1-5-18")
        self.assertTrue(root.find("t:Triggers/t:CalendarTrigger/t:StartBoundary", NS).text.endswith("T21:30:00"))
        self.assertEqual(root.find("t:Settings/t:StartWhenAvailable", NS).text, "true")


class AuditPolicy(unittest.TestCase):
    def test_plan_uses_guids_so_it_works_in_any_language(self):
        plan = local.audit_plan()
        auditpol = [c for c in plan if c[0] == "auditpol"]
        self.assertEqual(len(auditpol), len(local.AUDIT_SUBCATEGORIES))
        for command in auditpol:
            self.assertRegex(command[2], r"^/subcategory:\{[0-9A-F-]{36}\}$")
            self.assertIn("/success:enable", command)

    def test_plan_enables_process_creation_and_powershell_logging(self):
        plan = [" ".join(c) for c in local.audit_plan()]
        self.assertTrue(any("{0CCE922B-69AE-11D9-BED3-505054503030}" in c for c in plan))  # 4688
        self.assertTrue(any("{0CCE9227-69AE-11D9-BED3-505054503030}" in c for c in plan))  # 4698
        self.assertTrue(any("EnableScriptBlockLogging" in c for c in plan))
        self.assertTrue(any("ProcessCreationIncludeCmdLine_Enabled" in c for c in plan))


class SysmonConfig(unittest.TestCase):
    def setUp(self):
        self.root = ET.parse(local.SYSMON_CONFIG).getroot()

    def test_is_valid_sysmon_config(self):
        self.assertEqual(self.root.tag, "Sysmon")
        self.assertTrue(self.root.get("schemaversion"))
        self.assertIsNotNone(self.root.find("EventFiltering"))

    def test_logs_what_the_rules_need(self):
        def rules(tag, onmatch):
            return [e for e in self.root.iter(tag) if e.get("onmatch") == onmatch]

        self.assertTrue(rules("ProcessCreate", "exclude"))  # todos los procesos menos el ruido
        self.assertTrue(rules("WmiEvent", "exclude"))  # todo WMI
        lsass = [t.text for e in rules("ProcessAccess", "include") for t in e.iter("TargetImage")]
        self.assertIn(r"C:\Windows\system32\lsass.exe", lsass)
        keys = " ".join(t.text for e in rules("RegistryEvent", "include") for t in e.iter("TargetObject"))
        for key in (r"\CurrentVersion\Run", r"\Image File Execution Options", r"\Winlogon\Shell", r"\Control\Lsa"):
            self.assertIn(key, keys)

    def test_config_is_shipped_with_the_package(self):
        self.assertTrue(local.SYSMON_CONFIG.exists())


if __name__ == "__main__":
    unittest.main()
