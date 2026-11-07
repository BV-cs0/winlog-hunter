import re
import unittest

from helpers import ROOT

from winlog_hunter.rules import RULES

SIGMA = ROOT / "sigma"


class SigmaRules(unittest.TestCase):
    def test_every_rule_has_a_sigma_file(self):
        mapped = {}
        for path in SIGMA.glob("*.yml"):
            match = re.search(r"# winlog-hunter: (WLH-\d{3})", path.read_text(encoding="utf-8"))
            self.assertIsNotNone(match, f"{path.name} no indica su regla")
            mapped[match.group(1)] = path.name
        self.assertEqual(sorted(mapped), sorted(r.id for r in RULES))

    def test_files_have_required_sigma_fields(self):
        for path in SIGMA.glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            for field in ("title:", "id:", "logsource:" if "correlation:" not in text else "correlation:", "level:"):
                self.assertIn(field, text, f"{path.name}: falta {field}")


if __name__ == "__main__":
    unittest.main()
