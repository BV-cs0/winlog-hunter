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


if __name__ == "__main__":
    unittest.main()
