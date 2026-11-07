import os
import unittest
from pathlib import Path

from helpers import ROOT  # noqa: F401  (añade src al sys.path)

from winlog_hunter import pathfix


@unittest.skipUnless(os.name == "nt", "rutas de Windows")
class PathFix(unittest.TestCase):
    folder = Path(r"C:\Users\ana\AppData\Local\Python\pythoncore-3.15-64\Scripts")

    def test_detects_folder_on_path_ignoring_case_and_slashes(self):
        path = r"C:\Windows;c:\users\ANA\appdata\local\python\pythoncore-3.15-64\scripts\;C:\Tools"
        self.assertTrue(pathfix.on_path(self.folder, path))
        self.assertFalse(pathfix.on_path(self.folder, r"C:\Windows;C:\Tools"))

    def test_expands_variables_in_user_path(self):
        os.environ["WLH_TEST_HOME"] = r"C:\Users\ana"
        self.assertTrue(pathfix.on_path(self.folder, r"%WLH_TEST_HOME%\AppData\Local\Python\pythoncore-3.15-64\Scripts"))

    def test_joined_appends_without_double_separator(self):
        self.assertEqual(pathfix.joined("C:\A;", self.folder), f"C:\A;{self.folder}")
        self.assertEqual(pathfix.joined("", self.folder), str(self.folder))

    def test_never_runs_when_disabled(self):
        os.environ["WINLOG_HUNTER_NO_PATH"] = "1"
        try:
            pathfix.ensure_command_available()  # no debe tocar nada ni lanzar excepciones
        finally:
            del os.environ["WINLOG_HUNTER_NO_PATH"]


if __name__ == "__main__":
    unittest.main()
