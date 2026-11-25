"""Aviso de versión nueva: comparación de versiones y que la red nunca rompa nada."""

import io
import json
import os
import socket
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import helpers  # noqa: F401  (añade src/ al path)

from winlog_hunter import actualizacion as act


class Terminal(io.StringIO):
    def isatty(self):
        return True


class TestVersiones(unittest.TestCase):
    def test_comparacion(self):
        casos = [
            ("0.6.0", "0.7.0", True), ("0.6.0", "0.6.1", True), ("0.6.0", "1.0", True),
            ("0.9.0", "0.10.0", True), ("0.6.0", "0.6.0", False), ("0.6.0", "0.6", False),
            ("0.7.0", "0.6.9", False), ("0.6.0", "0.7.0rc1", False), ("0.6.0", "1.0.dev2", False),
            ("0.6.0", "", False), ("0.6.0", "basura", False), ("raro", "9.9.9", False),
        ]
        for actual, ultima, esperado in casos:
            with self.subTest(actual=actual, ultima=ultima):
                self.assertIs(act.hay_version_nueva(actual, ultima), esperado)

    def test_tipos_inesperados(self):
        self.assertFalse(act.hay_version_nueva("0.6.0", None))
        self.assertFalse(act.hay_version_nueva("0.6.0", 7))


class TestRed(unittest.TestCase):
    def test_fallos_de_red_devuelven_none(self):
        errores = [urllib.error.URLError("sin red"), socket.timeout("lento"), ConnectionResetError(),
                   OSError("caído"), ValueError("raro")]
        for error in errores:
            with self.subTest(error=type(error).__name__), patch("urllib.request.urlopen", side_effect=error):
                self.assertIsNone(act.consultar_pypi())

    def test_respuestas_raras_devuelven_none(self):
        for cuerpo in (b"no es json", b"{}", b'{"info": {"version": "1.0rc1"}}', b'{"info": {"version": 3}}'):
            respuesta = io.BytesIO(cuerpo)
            with self.subTest(cuerpo=cuerpo), patch("urllib.request.urlopen", return_value=respuesta):
                self.assertIsNone(act.consultar_pypi())

    def test_respuesta_buena(self):
        with patch("urllib.request.urlopen", return_value=io.BytesIO(b'{"info": {"version": "0.7.0"}}')):
            self.assertEqual(act.consultar_pypi(), "0.7.0")


class TestAviso(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ruta = Path(self._tmp.name) / "version.json"
        self._env = patch.dict(os.environ, {act.VARIABLE_DESACTIVAR: ""})
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def _iniciar(self, flujo=None, ahora=1_000_000.0, consultar=lambda: "0.7.0"):
        flujo = flujo if flujo is not None else Terminal()
        hilo = act.iniciar("0.6.0", flujo=flujo, ruta=self.ruta, ahora=lambda: ahora, consultar=consultar)
        if hilo:
            hilo.join(2)
        return flujo.getvalue(), hilo

    def test_sin_terminal_no_consulta_ni_avisa(self):
        salida, hilo = self._iniciar(flujo=io.StringIO())
        self.assertEqual(salida, "")
        self.assertIsNone(hilo)
        self.assertFalse(self.ruta.exists())

    def test_variable_de_entorno_lo_desactiva(self):
        with patch.dict(os.environ, {act.VARIABLE_DESACTIVAR: "1"}):
            salida, hilo = self._iniciar()
        self.assertEqual((salida, hilo), ("", None))

    def test_avisa_una_sola_vez_por_version_y_al_arrancar_siguiente(self):
        salida, hilo = self._iniciar()            # 1ª vez: consulta en segundo plano, sin aviso aún
        self.assertEqual(salida, "")
        self.assertIsNotNone(hilo)
        salida, hilo = self._iniciar()            # 2ª vez: avisa con lo guardado y no vuelve a consultar
        self.assertEqual(salida.count("\n"), 1)
        self.assertIn("0.7.0", salida)
        self.assertIn("pip install -U winlog-hunter", salida)
        self.assertIsNone(hilo)
        salida, _ = self._iniciar()               # 3ª vez: ya avisado de esa versión
        self.assertEqual(salida, "")

    def test_consulta_como_mucho_una_vez_al_dia(self):
        self._iniciar(ahora=1_000_000.0)
        _, hilo = self._iniciar(ahora=1_000_000.0 + act.INTERVALO - 1)
        self.assertIsNone(hilo)
        _, hilo = self._iniciar(ahora=1_000_000.0 + act.INTERVALO + 1)
        self.assertIsNotNone(hilo)

    def test_fallo_de_red_en_el_hilo_no_se_propaga_ni_guarda_nada(self):
        def explota():
            raise urllib.error.URLError("sin red")

        salida, hilo = self._iniciar(consultar=explota)
        self.assertEqual(salida, "")
        self.assertFalse(self.ruta.exists())
        self.assertFalse(hilo.is_alive())

    def test_estado_corrupto_o_carpeta_sin_permiso_no_rompe(self):
        self.ruta.write_text("{roto", encoding="utf-8")
        salida, _ = self._iniciar()
        self.assertEqual(salida, "")
        ruta_imposible = Path(self._tmp.name) / "archivo" / "version.json"
        (Path(self._tmp.name) / "archivo").write_text("no soy carpeta", encoding="utf-8")
        hilo = act.iniciar("0.6.0", flujo=Terminal(), ruta=ruta_imposible, ahora=lambda: 1.0,
                           consultar=lambda: "0.7.0")
        hilo.join(2)

    def test_version_instalada_mas_nueva_no_avisa(self):
        self.ruta.write_text(json.dumps({"ultima": "0.5.0", "comprobado": 1_000_000.0}), encoding="utf-8")
        salida, _ = self._iniciar()
        self.assertEqual(salida, "")


if __name__ == "__main__":
    unittest.main()
