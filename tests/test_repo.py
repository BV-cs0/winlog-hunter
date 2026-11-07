import re
import unittest

from helpers import ROOT

from winlog_hunter import __version__


class Repository(unittest.TestCase):
    def test_versions_match(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(f'version = "{__version__}"', pyproject)

    def test_readme_badge_shows_current_version(self):
        # La insignia es estática para que GitHub no muestre una versión antigua en caché.
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        badge = re.search(r"img\.shields\.io/badge/PyPI-v([0-9.]+)-", readme)
        self.assertIsNotNone(badge, "falta la insignia de PyPI en el README")
        self.assertEqual(badge.group(1), __version__, "actualiza la insignia de PyPI del README")


class Help(unittest.TestCase):
    def test_help_is_in_spanish_and_lists_every_command(self):
        import contextlib
        import io

        from winlog_hunter.cli import main

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main([]), 0)
        text = out.getvalue()
        self.assertIn("uso: winlog-hunter", text)
        for command in ("analyze", "rules", "equipo", "programar", "sysmon", "auditoria", "desinstalar"):
            self.assertIn(command, text)


if __name__ == "__main__":
    unittest.main()
