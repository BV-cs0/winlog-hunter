"""Exclusiones estrictas, trazables y posteriores a la detección."""

import contextlib
import csv
import io
import json
import tempfile
import unittest
import warnings
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import patch

from helpers import ROOT, SAMPLE
from winlog_hunter import exclusiones as ex, local
from winlog_hunter.cli import main
from winlog_hunter.models import Finding
from winlog_hunter.report import RENDERERS, Stats, render_console


class Exclusiones(unittest.TestCase):
    def setUp(self):
        base = ROOT / '.medidas'
        base.mkdir(exist_ok=True)
        temporal = patch.object(tempfile, 'tempdir', str(base))
        temporal.start()
        self.addCleanup(temporal.stop)
        self.tmp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.path = self.folder / 'exclusiones.json'
        self.hoy = date(2026, 11, 13)
        ahora = datetime(2026, 11, 13, tzinfo=timezone.utc)
        self.f = Finding('WLH-007', 'Tarea', 'high', [], 'Cuenta svc_backup', ahora, ahora,
                         ['PC-UNO', 'SERVIDOR'], {'tarea': [r'\Antivirus\Diaria', 'otra'],
                         'datos': {'cuenta': 'Svc_Backup'}, 'numero': 42}, 12, veces=6)

    def guardar(self, item=None, documento=None):
        if documento is None:
            documento = {'version': 1, 'exclusiones': [dict(motivo='Actividad autorizada', **(item or {}))]}
        self.path.write_text(json.dumps(documento, ensure_ascii=False), encoding='utf-8')
        return self.path

    def aplicar(self, item):
        return ex.aplicar([self.f], ex.cargar(self.guardar(item)), self.hoy)

    def test_validacion_estricta(self):
        casos = [
            ([], 'documento'), ({'version': 2, 'exclusiones': []}, 'version'),
            ({'version': True, 'exclusiones': []}, 'version'),
            ({'version': 1}, 'exclusiones'),
            ({'version': 1, 'exclusiones': {}, 'extra': 1}, 'documento.extra'),
            ({'version': 1, 'exclusiones': [False]}, 'exclusiones[0]'),
            ({'version': 1, 'exclusiones': [{'texto': 'x'}]}, 'exclusiones[0].motivo'),
        ]
        for documento, ruta in casos:
            with self.subTest(documento=documento), self.assertRaisesRegex(ValueError, ruta.replace('[', r'\[').replace(']', r'\]')):
                ex.cargar(self.guardar(documento=documento))

    def test_errores_de_cada_campo(self):
        casos = [({}, 'exclusiones[0]'), ({'motivo': ' '}, '.motivo'),
                 ({'desconocida': 1}, '.desconocida'), ({'reglas': []}, '.reglas'),
                 ({'reglas': '*'}, '.reglas'), ({'reglas': [1]}, '.reglas[0]'),
                 ({'reglas': ['WLH-999']}, '.reglas[0]'), ({'reglas': ['WLH-*']}, '.reglas[0]'),
                 ({'equipos': []}, '.equipos'), ({'equipos': ['']}, '.equipos[0]'),
                 ({'campos': []}, '.campos'), ({'campos': {}}, '.campos'),
                 ({'campos': {'': '*'}}, '.campos'), ({'campos': {'tarea': 1}}, '.campos.tarea'),
                 ({'texto': ''}, '.texto'), ({'texto': False}, '.texto'),
                 ({'severidad_maxima': []}, '.severidad_maxima'),
                 ({'severidad_maxima': 'alta'}, '.severidad_maxima'),
                 ({'caduca': '2026-02-30'}, '.caduca'), ({'caduca': 123}, '.caduca'),
                 ({'caduca': '2026-1-01'}, '.caduca')]
        for item, ruta in casos:
            with self.subTest(item=item):
                documento = {'version': 1, 'exclusiones': [{'motivo': 'Justificación', **item}]}
                with self.assertRaises(ValueError) as cm:
                    ex.cargar(self.guardar(documento=documento))
                self.assertIn(ruta, str(cm.exception))

    def test_json_invalido_duplicado_y_fichero_ausente(self):
        for contenido in ('{', '{"version":1,"version":1,"exclusiones":[]}'):
            self.path.write_text(contenido, encoding='utf-8')
            with self.assertRaises(ValueError):
                ex.cargar(self.path)
        with self.assertRaises(ValueError):
            ex.cargar(self.folder / 'ausente.json')

    def test_todos_los_ids_existentes(self):
        self.assertEqual(len(ex.cargar(self.guardar({'reglas': [f'WLH-{i:03}' for i in range(1, 37)]}))), 1)

    def test_cada_criterio_positivo(self):
        for item in ({'reglas': ['WLH-001', 'WLH-007']}, {'reglas': ['*']},
                     {'equipos': ['NO', 'pc-?no']}, {'campos': {'tarea': r'\antivirus\*'}},
                     {'campos': {'numero': '4?'}}, {'texto': 'SVC_BACKUP'},
                     {'severidad_maxima': 'high'}, {'caduca': '2026-11-13'}):
            with self.subTest(item=item):
                visibles, ocultos = self.aplicar(item)
                self.assertEqual(visibles, [])
                self.assertEqual(ocultos, [{'rule_id': 'WLH-007', 'summary': self.f.summary, 'veces': self.f.veces, 'motivo': 'Actividad autorizada'}])
                self.assertEqual(self.f.veces, 6)

    def test_cada_criterio_negativo(self):
        for item in ({'reglas': ['WLH-001']}, {'equipos': ['PC-DOS']},
                     {'campos': {'inexistente': '*'}}, {'campos': {'tarea': 'no'}},
                     {'texto': 'desconocido'}, {'severidad_maxima': 'medium'}):
            with self.subTest(item=item):
                self.assertEqual(self.aplicar(item), ([self.f], []))

    def test_texto_sobre_evidencias_anidadas(self):
        self.f.summary = 'Resumen'
        self.assertFalse(self.aplicar({'texto': 'SVC_BACKUP'})[0])

    def test_combinacion_y_entre_campos_y_criterios(self):
        item = {'reglas': ['WLH-007'], 'equipos': ['pc-*'], 'campos': {'tarea': '*diaria', 'numero': '42'}, 'texto': 'backup'}
        self.assertFalse(self.aplicar(item)[0])
        item['campos']['numero'] = '43'
        self.assertEqual(self.aplicar(item), ([self.f], []))
        item['campos']['numero'] = '42'
        item['equipos'] = ['OTRO']
        self.assertEqual(self.aplicar(item), ([self.f], []))

    def test_caducidad_avisa_incluso_sin_hallazgos(self):
        elementos = ex.cargar(self.guardar({'caduca': '2026-11-12'}))
        with warnings.catch_warnings(record=True) as avisos:
            warnings.simplefilter('always')
            self.assertEqual(ex.aplicar([self.f], elementos, self.hoy), ([self.f], []))
            self.assertEqual(len(avisos), 1)
            self.assertIn('Actividad autorizada', str(avisos[0].message))
        avisos = []
        ex.aplicar_con_avisos([], elementos, self.hoy, avisos)
        self.assertIn('caducada', avisos[0])

    def test_orden_de_severidades(self):
        for severidad in ('low', 'medium', 'high', 'critical'):
            self.f.severity = severidad
            self.assertEqual(bool(self.aplicar({'severidad_maxima': 'high'})[0]), severidad == 'critical')

    def test_primera_coincidencia_y_sin_exclusiones(self):
        self.assertEqual(ex.aplicar([self.f], [], self.hoy), ([self.f], []))
        es = [ex.Exclusion('Primera', texto='backup'), ex.Exclusion('Segunda', reglas=['*'])]
        self.assertEqual(ex.aplicar([self.f], es, self.hoy)[1][0]['motivo'], 'Primera')

    def test_informes_y_escape_de_motivos(self):
        motivo = '<script>|=fórmula\n'
        stats = Stats(1, 1, excluidos=[{'rule_id': self.f.rule_id, 'summary': self.f.summary, 'motivo': motivo}])
        self.assertIn('Hallazgos excluidos: 1', render_console([], stats))
        self.assertIn('1 por:', RENDERERS['markdown']([], stats))
        html = RENDERERS['html']([], stats)
        self.assertIn('&lt;script&gt;', html)
        self.assertNotIn('<script>', html)
        self.assertEqual(json.loads(RENDERERS['json']([], stats))['excluidos'], stats.excluidos)
        filas = list(csv.DictReader(io.StringIO(RENDERERS['csv']([], stats))))
        self.assertEqual(filas[0]['estado'], 'excluido')
        self.assertIn('fórmula', filas[0]['motivo'])
        stats.excluidos[0]['motivo'] = '=fórmula'
        self.assertIn("'=fórmula", RENDERERS['csv']([], stats))

    def test_resolver_predeterminada_explicita_y_desactivada(self):
        self.guardar({'texto': 'backup'})
        self.assertEqual(len(ex.resolver(predeterminada=self.path)), 1)
        self.assertEqual(ex.resolver(predeterminada=self.folder / 'ausente'), [])
        self.assertEqual(ex.resolver(self.folder / 'ausente', True, self.path), [])
        with self.assertRaises(ValueError):
            ex.resolver(self.folder / 'ausente', predeterminada=self.path)
        with patch.dict('os.environ', {'ProgramData': str(self.folder)}):
            self.assertEqual(ex.ruta_predeterminada(), self.folder / 'winlog-hunter' / 'exclusiones.json')

    def test_cli_plantilla_validacion_y_error(self):
        salida, errores = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(salida):
            self.assertEqual(main(['exclusiones', '--plantilla']), 0)
        self.path.write_text(salida.getvalue(), encoding='utf-8')
        self.assertTrue(ex.cargar(self.path))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['exclusiones', '--validar', str(self.path)]), 0)
        with contextlib.redirect_stderr(errores):
            self.assertEqual(main(['exclusiones', '--validar', str(self.folder / 'ausente')]), 2)
        self.assertIn('error:', errores.getvalue())

    def test_analyze_filtra_y_fail_on_usa_visibles(self):
        self.guardar({'reglas': ['*']})
        salida = self.folder / 'informe.json'
        args = ['analyze', str(SAMPLE), '--procesos', '1', '--fail-on', 'low', '-o', str(salida)]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(args + ['--exclusiones', str(self.path)]), 0)
            data = json.loads(salida.read_text(encoding='utf-8'))
            self.assertEqual(data['findings'], [])
            self.assertTrue(data['excluidos'])
            self.assertEqual(main(args + ['--sin-exclusiones']), 1)
            self.assertEqual(json.loads(salida.read_text(encoding='utf-8'))['excluidos'], [])

    def test_equipo_usa_predeterminada_y_permite_desactivar(self):
        self.guardar({'reglas': ['*']})
        def exportar(horas, carpeta):
            return local.Export([SAMPLE], [])
        for desactivar in (False, True):
            with patch.dict('os.environ', {'TMP': str(self.folder), 'TEMP': str(self.folder)}):
                resultado = local.analyze_this_computer(output=self.folder / str(desactivar), exporter=exportar,
                    log=lambda m: None, notify_from=None, ruta_exclusiones=self.path, sin_exclusiones=desactivar)
            data = json.loads(resultado.json.read_text(encoding='utf-8'))
            self.assertEqual(bool(data['findings']), desactivar)
            self.assertEqual(bool(data['excluidos']), not desactivar)

    def test_analyze_no_carga_predeterminada_y_rechaza_configuracion_mala(self):
        self.path.write_text('{}', encoding='utf-8')
        salida = self.folder / 'informe.json'
        args = ['analyze', str(SAMPLE), '--procesos', '1', '-o', str(salida)]
        with patch.object(ex, 'ruta_predeterminada', side_effect=AssertionError('No debe consultar ProgramData')):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 0)
                self.assertEqual(main(args + ['--exclusiones', str(self.path)]), 2)

    def test_caducidad_conservada_en_todos_los_informes(self):
        self.guardar({'reglas': ['*'], 'caduca': '2000-01-01'})
        # El CSV es solo la tabla de hallazgos: los avisos van en los demás formatos.
        for formato in ('console', 'json', 'markdown', 'html'):
            with self.subTest(formato=formato):
                salida = self.folder / ('informe.' + formato)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(['analyze', str(SAMPLE), '--procesos', '1',
                        '--exclusiones', str(self.path), '-f', formato, '-o', str(salida)]), 0)
                self.assertIn('Exclusión caducada', salida.read_text(encoding='utf-8'))

    def test_cli_equipo_y_programar_transmiten_ruta(self):
        self.guardar({'reglas': ['*']})
        with patch.object(local, 'require_windows'), patch.object(local, 'is_admin', return_value=True), patch.object(local, 'analyze_this_computer') as analizar:
            analizar.return_value.exit_code = 0
            self.assertEqual(main(['equipo', '--sin-abrir', '--exclusiones', str(self.path)]), 0)
            self.assertEqual(analizar.call_args.kwargs['exclusiones'], self.path)
        with patch.object(local, 'schedule') as programar, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['programar', '--exclusiones', str(self.path), '--salida', str(self.folder)]), 0)
            self.assertEqual(programar.call_args.kwargs['exclusiones'], self.path)

    def test_programar_valida_predeterminada_y_propaga_explicita(self):
        self.guardar({'texto': 'backup'})
        proceso = type('Proceso', (), {'returncode': 0})()
        with patch.object(local, 'require_windows'), patch.object(local, '_require_admin'), patch.object(local, '_run', return_value=proceso), patch.object(local, 'resolver', wraps=ex.resolver) as resolver:
            local.schedule('09:00', 24, self.folder, 'critical', ruta_exclusiones=self.path)
            resolver.assert_called_once_with(None, predeterminada=self.path)
        xml = local.task_xml('09:00', 24, self.folder, 'critical', exclusiones=self.path)
        self.assertIn('--exclusiones', xml)
        self.assertIn(str(self.path.resolve()), xml)
        self.path.write_text('{}', encoding='utf-8')
        with patch.object(local, 'require_windows'), patch.object(local, '_require_admin'), self.assertRaises(ValueError):
            local.schedule('09:00', 24, self.folder, 'critical', ruta_exclusiones=self.path)

    def test_carga_utf16_y_codificacion_local(self):
        """Lo que genera `--plantilla > fichero` en PowerShell 5.1 o en cmd debe validarse."""
        import json as _json
        texto = _json.dumps(ex.PLANTILLA, ensure_ascii=False)
        for codificacion in ('utf-16', 'utf-8-sig', 'cp1252'):
            with self.subTest(codificacion=codificacion):
                self.path.write_bytes(texto.encode(codificacion))
                # La codificación local de un Windows en español; en Linux sería UTF-8
                with patch.object(ex.locale, 'getpreferredencoding', return_value='cp1252'):
                    self.assertEqual(ex.cargar(self.path)[0].motivo, 'Tarea legítima del antivirus corporativo')
