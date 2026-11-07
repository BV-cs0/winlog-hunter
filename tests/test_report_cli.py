import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from helpers import SAMPLE, ev

from winlog_hunter.cli import main
from winlog_hunter.report import Stats, render_console, render_html, render_markdown
from winlog_hunter.rules import run_rules

EVIL = "<script>alert(1)</script>\x1b[31m"


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


class ReportEscaping(unittest.TestCase):
    def setUp(self):
        self.findings = run_rules([ev(4720, TargetUserName=EVIL, SubjectUserName="x")])
        self.stats = Stats(events=1, files=1)

    def test_html_escapes_log_content(self):
        page = render_html(self.findings, self.stats)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("Content-Security-Policy", page)

    def test_console_strips_control_characters(self):
        self.assertNotIn("\x1b", render_console(self.findings, self.stats, color=False))

    def test_markdown_escapes_html(self):
        self.assertNotIn("<script>", render_markdown(self.findings, self.stats))


class CommandLine(unittest.TestCase):
    EXPECTED = {f"WLH-{n:03d}" for n in range(1, 13)}

    def test_sample_scenario_triggers_every_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "informe.json"
            code, _, err = run_cli("analyze", str(SAMPLE), "-o", str(out))
            self.assertEqual(code, 0)
            self.assertIn("guardado", err)
            report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual({f["rule_id"] for f in report["findings"]}, self.EXPECTED)
        self.assertEqual(report["stats"]["findings_by_severity"]["critical"], 3)

    def test_min_severity_and_fail_on(self):
        code, out, _ = run_cli("analyze", str(SAMPLE), "--min-severity", "critical", "--fail-on", "high", "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("Hallazgos: 3", out)
        self.assertNotIn("[ALTA]", out)

    def test_fail_on_ignores_display_filter(self):
        # Solo hay hallazgos ALTOS (WLH-001); ocultarlos no debe evitar el fallo.
        code, out, _ = run_cli("analyze", str(SAMPLE), "--rules", "WLH-001",
                               "--min-severity", "critical", "--fail-on", "high", "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("Hallazgos: 0", out)

    def test_rule_filter(self):
        code, out, _ = run_cli("analyze", str(SAMPLE), "--rules", "wlh-005", "-f", "json")
        self.assertEqual(code, 0)
        self.assertEqual([f["rule_id"] for f in json.loads(out)["findings"]], ["WLH-005"])

    def test_errors(self):
        self.assertEqual(run_cli("analyze", str(SAMPLE), "--rules", "WLH-999")[0], 2)
        self.assertEqual(run_cli("analyze", "no-existe.jsonl")[0], 2)

    def test_rules_listing(self):
        code, out, _ = run_cli("rules")
        self.assertEqual(code, 0)
        self.assertEqual(out.count("WLH-"), 12)


if __name__ == "__main__":
    unittest.main()
