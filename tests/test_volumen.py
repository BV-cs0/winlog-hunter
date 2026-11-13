"""Regresión de la selección, streaming y procesamiento de grandes volúmenes."""

import io
import json
import pickle
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stderr
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from helpers import BASE, SAMPLE, ev, sysmon
from winlog_hunter import parsers
from winlog_hunter.cli import main
from winlog_hunter.models import Event
from winlog_hunter.report import Stats, render_html, render_json, render_console, render_csv
from winlog_hunter.rules import RULES, Config, Rule, planificar, run_rules
from winlog_hunter.rules import base


def xml_event(i=4625):
    return (f'<Event><System><EventID>{i}</EventID><EventRecordID>1</EventRecordID>'
            '<TimeCreated SystemTime="2026-11-03T09:00:00Z"/><Channel>Security</Channel>'
            '<Computer>PC</Computer></System><EventData><Data Name="x">áéíóú</Data></EventData></Event>')


class SeleccionReglas(unittest.TestCase):
    def test_todas_declaran_eventos(self):
        self.assertTrue(all(r.eventos for r in RULES))

    def test_indice_entrega_solo_lo_pedido_y_conserva_empates(self):
        recibidos = []
        def recoger(events, config):
            recibidos.extend(events)
            return []
        regla = Rule("PRUEBA", "", "low", (), "", recoger,
                     frozenset({7, ("security", 8)}), lambda e: e.get("usar") != "no")
        events = [ev(8), ev(7), ev(9), ev(8, channel="System"), ev(7, usar="no")]
        with patch.object(base, "RULES", [regla]):
            self.assertEqual(run_rules(events), [])
        self.assertEqual(recibidos, events[:2])

    def test_union_de_predicados(self):
        a = Rule("A", "", "low", (), "", None, frozenset({5156}), lambda e: e.get("puerto") == "3389")
        b = Rule("B", "", "low", (), "", None, frozenset({5156}))
        self.assertFalse(planificar([a]).acepta(ev(5156, puerto="80")))
        self.assertTrue(planificar([a, b]).acepta(ev(5156, puerto="80")))

    def test_filtro_real_5156(self):
        r = next(r for r in RULES if r.id == "WLH-031")
        self.assertFalse(r.acepta(ev(5156, DestPort="80")))
        self.assertTrue(r.acepta(ev(5156, DestPort="3389")))

    def test_event_ligero_y_serializable(self):
        e = ev(4625, usuario="ana")
        self.assertFalse(hasattr(e, "__dict__"))
        self.assertEqual(pickle.loads(pickle.dumps(e)), e)
        other = ev(4625, usuario="otro")
        self.assertIs(e.channel, other.channel)
        self.assertIs(next(iter(e.data)), next(iter(other.data)))

    def test_agrupacion_respeta_equipo_severidad_clave_y_fechas(self):
        events = [ev(7045, n, computer=host, ServiceName=nombre, ImagePath=ruta)
                  for n, host, nombre, ruta in [
                      (0, "A", "x", "normal.exe"), (10, "A", "x", "normal.exe"),
                      (20, "B", "x", "normal.exe"), (30, "A", "y", "normal.exe"),
                      (40, "A", "x", "cmd.exe /c whoami")]]
        findings = run_rules(events, only={"WLH-006"})
        self.assertEqual(len(findings), 4)
        grouped = next(f for f in findings if f.veces == 2)
        self.assertEqual(grouped.event_count, 2)
        self.assertEqual(grouped.last_seen - grouped.first_seen, timedelta(seconds=10))
        self.assertIn("×2", render_html(findings, Stats(5, 1)))
        self.assertIn("×2", render_console(findings, Stats(5, 1), color=False))


class Streaming(unittest.TestCase):
    def test_pull_parser_entrega_pronto_y_libera_nodos(self):
        creados = []
        raices = []
        original = ET.XMLPullParser
        class Auditor(original):
            def read_events(self):
                for action, node in super().read_events():
                    if action == "start" and node.tag == "WlhRoot":
                        raices.append(node)
                    yield action, node
        def chunks():
            for i in range(20000):
                creados.append(i)
                yield xml_event()
        with patch.object(parsers.ET, "XMLPullParser", Auditor):
            iterator = parsers._events_from_xml_chunks(chunks(), Path("prueba.xml"), self.fail)
            self.assertEqual(next(iterator).get("x"), "áéíóú")
            self.assertLess(len(creados), 10)
            self.assertEqual(sum(1 for _ in iterator), 19999)
        self.assertEqual(len(raices[0]), 0)

    def test_doctype_dividido_entre_fragmentos(self):
        warnings = []
        result = list(parsers._events_from_xml_chunks(["<!DOC", 'TYPE x [<!ENTITY a "x">]>', xml_event()],
                                                       Path("mal.xml"), warnings.append))
        self.assertEqual(result, [])
        self.assertTrue(any("DOCTYPE" in w for w in warnings))

    def test_declaracion_xml_dividida_y_bom(self):
        text = '<?xml version="1.0" encoding="utf-16"?>' + xml_event() + xml_event(1102)
        warnings = []
        events = list(parsers._events_from_xml_chunks((text[i:i+3] for i in range(0,len(text),3)),
                                                      Path("prueba.xml"), warnings.append))
        self.assertEqual(warnings, [])
        self.assertEqual([e.event_id for e in events], [4625,1102])

    def test_descarta_json_antes_de_construir_event(self):
        with patch.object(parsers, "Event", side_effect=AssertionError("no debe construirse")):
            selection = parsers.Seleccion(planificar())
            self.assertIsNone(parsers.event_from_dict({"EventID":4634,"TimeCreated":"2026-11-03"}, selection))
        self.assertEqual((selection.leidos, selection.descartados), (1,1))

    def test_xpath_troceada_disjunta_y_con_cotas(self):
        import re
        ids = set(range(100,180))
        queries = list(parsers.consultas_xpath(ids, BASE, BASE+timedelta(days=1), (1,1000)))
        result = []
        for q in queries:
            found = [int(x) for x in re.findall(r"EventID=(\d+)",q)]
            self.assertLessEqual(len(found)+4,parsers.XPATH_COMPARACIONES)
            self.assertIn("EventRecordID>=1",q)
            self.assertIn("TimeCreated",q)
            self.assertNotIn("+00:00",q)
            result.extend(found)
        self.assertEqual(set(result), ids)
        self.assertEqual(len(result),len(ids))

    def test_xpath_rechazada_recurre_a_filtro_python(self):
        import os
        if os.name != "nt":
            self.skipTest("consulta nativa de Windows")
        warnings = []
        selection = parsers.Seleccion(planificar())
        with patch.object(parsers.shutil, "which", return_value="wevtutil"), \
             patch.object(parsers, "_wevtutil_chunks", side_effect=[parsers.ErrorConsulta("consulta no válida"), iter([xml_event(4720)])]) as stream, \
             patch.object(parsers, "informacion_evtx", return_value={"numberOfLogRecords": 1}):
            events = list(parsers.load_evtx(Path("log.evtx"), warnings.append, selection))
        self.assertEqual([e.event_id for e in events], [4720])
        self.assertEqual(stream.call_count, 2)
        self.assertIsInstance(stream.call_args_list[0].args[1], list)
        self.assertEqual(stream.call_args_list[1].args, (Path("log.evtx"), "*"))
        self.assertIn("filtro en Python", warnings[0])

    def test_consulta_estructurada_escapa_ruta_y_cada_select_respeta_limite(self):
        import codecs
        path=Path('á & carpeta')/'log.evtx'
        queries=list(parsers.consultas_xpath(planificar().ids,BASE,BASE))
        document=parsers.consulta_estructurada(path,queries)
        self.assertTrue(document.startswith(codecs.BOM_UTF8))
        root=ET.fromstring(document)
        selects=root.findall("./Query/Select")
        self.assertEqual(len(selects),4)
        self.assertEqual([s.text for s in selects],queries)
        self.assertTrue(all(s.get("Path")=="file://"+str(path.resolve()) for s in selects))

    def test_consulta_temporal_se_elimina_y_solo_lanza_un_proceso(self):
        rutas=[]
        def leer(command):
            self.assertIn("/sq:true",command)
            path=Path(command[2]);rutas.append(path)
            self.assertTrue(path.exists())
            self.assertEqual(len(ET.parse(path).getroot().findall("./Query/Select")),3)
            yield xml_event(4720)
        with patch.object(parsers,"_leer_wevtutil",side_effect=leer) as run:
            self.assertEqual(list(parsers._wevtutil_chunks(Path("a.evtx"),list(parsers.consultas_xpath(planificar().ids)))),[xml_event(4720)])
        self.assertEqual(run.call_count,1)
        self.assertFalse(rutas[0].exists())

    def test_gli_solo_con_estadisticas_o_progreso(self):
        import os
        if os.name != "nt":self.skipTest("consulta nativa de Windows")
        for stats, progress in ((False,False),(True,False),(False,True)):
            selection=parsers.Seleccion(planificar(),estadisticas=stats,progreso=progress)
            with patch.object(parsers.shutil,"which",return_value="wevtutil"), \
                 patch.object(parsers,"_wevtutil_chunks",return_value=iter([xml_event(4720)])), \
                 patch.object(parsers,"informacion_evtx",return_value={"numberOfLogRecords":10}) as gli:
                events=list(parsers.load_evtx(Path("a.evtx"),self.fail,selection))
            self.assertEqual(len(events),1)
            self.assertEqual(gli.call_count,int(stats or progress))
            self.assertEqual(selection.leidos,10 if stats or progress else 1)

    def test_error_tras_emitir_eventos_no_repite_la_lectura(self):
        import os
        if os.name != "nt":self.skipTest("consulta nativa de Windows")
        def fragmentos():
            yield xml_event(4720)+"<Event>"
            raise parsers.ErrorConsulta("error después del primer evento")
        warnings=[]
        with patch.object(parsers.shutil,"which",return_value="wevtutil"), \
             patch.object(parsers,"_wevtutil_chunks",return_value=fragmentos()) as stream:
            events=list(parsers.load_evtx(Path("a.evtx"),warnings.append,parsers.Seleccion(planificar())))
        self.assertEqual(len(events),1)
        self.assertEqual(stream.call_count,1)
        self.assertIn("tras 1 eventos",warnings[0])

    def test_ruta_con_ampersand_usa_una_pasada_y_filtro_python(self):
        import os
        if os.name != "nt":self.skipTest("consulta nativa de Windows")
        path=Path("a & b.evtx")
        with patch.object(parsers.shutil,"which",return_value="wevtutil"), \
             patch.object(parsers,"_wevtutil_chunks",return_value=iter([xml_event(4720)])) as stream:
            events=list(parsers.load_evtx(path,self.fail,parsers.Seleccion(planificar())))
        self.assertEqual(len(events),1)
        stream.assert_called_once_with(path,"*")


class RepetidosYCache(unittest.TestCase):
    def test_nuevas_reglas_agrupan_acciones_identicas(self):
        from copy import deepcopy
        cases={
            10:sysmon(0,r'C:\Windows\System32\powershell.exe','powershell -nop -w hidden'),
            11:sysmon(0,r'C:\Windows\System32\certutil.exe','certutil -urlcache http://ejemplo.invalid/a'),
            12:sysmon(0,r'C:\Windows\System32\cmd.exe','cmd /c whoami',parent=r'C:\Office\winword.exe'),
            18:sysmon(0,r'C:\Windows\System32\cmd.exe','cmd /c whoami',parent=r'C:\Windows\System32\wmiprvse.exe'),
            19:ev(13,channel='Sysmon',Image=r'C:\Users\ana\reg.exe',TargetObject=r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Prueba',Details='cmd.exe /c whoami'),
            22:ev(13,channel='Sysmon',Image=r'C:\Users\ana\reg.exe',TargetObject=r'HKCU\Software\Classes\ms-settings\shell\open\command',Details='cmd.exe'),
            23:sysmon(0,r'C:\Users\ana\svchost.exe','svchost.exe'),
            24:sysmon(0,r'C:\Windows\System32\cmd.exe','cmd /c whoami',parent=r'C:\Windows\System32\w3wp.exe'),
            25:sysmon(0,r'C:\Windows\System32\vssadmin.exe','vssadmin delete shadows /all'),
            27:ev(7,channel='Sysmon',Image=r'C:\Windows\System32\svchost.exe',ImageLoaded=r'C:\Users\ana\wlbsctrl.dll',Signed='false'),
            28:ev(17,channel='Sysmon',PipeName=r'\postex_1234',Image=r'C:\Users\ana\a.exe'),
            29:ev(13,channel='Sysmon',Image=r'C:\Users\ana\reg.exe',TargetObject=r'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',Details='0'),
        }
        for n,event in cases.items():
            with self.subTest(regla=n):
                other=deepcopy(event);other.timestamp+=timedelta(hours=1)
                other.data.update(ProcessGuid='otra-instancia',ProcessId='999')
                findings=run_rules([event,other],only={f'WLH-{n:03d}'})
                self.assertEqual(len(findings),1)
                self.assertEqual((findings[0].veces,findings[0].event_count),(2,2))
                self.assertEqual(findings[0].last_seen-other.timestamp,timedelta(0))

    def test_no_agrupa_campos_truncados_distintos_ni_padres_omitidos_en_evidencia(self):
        from copy import deepcopy
        first=sysmon(0,r'C:\Windows\System32\cmd.exe','cmd /c '+ 'x'*800+'a',parent=r'C:\Office\winword.exe')
        second=deepcopy(first);second.data['CommandLine']=second.data['CommandLine'][:-1]+'b'
        self.assertEqual(len(run_rules([first,second],only={'WLH-012'})),2)
        first=sysmon(0,r'C:\Users\ana\svchost.exe','svchost.exe')
        second=deepcopy(first);second.data['ParentImage']=r'C:\Windows\System32\cmd.exe'
        self.assertEqual(len(run_rules([first,second],only={'WLH-023'})),2)
        first=ev(1040,channel='Application',provider='MsiInstaller',Data0='https://ejemplo.invalid/'+'x'*800+'a')
        second=deepcopy(first);second.data['Data0']=second.data['Data0'][:-1]+'b'
        self.assertEqual(len(run_rules([first,second],only={'WLH-011'})),2)

    def test_conserva_diferencias_en_evidencias_no_incluidas_en_la_clave(self):
        events=[ev(7045,ServiceName='x',ImagePath='normal.exe',StartType=start) for start in ('auto','manual')]
        self.assertEqual(len(run_rules(events,only={'WLH-006'})),2)

    def test_no_agrupa_correlaciones_de_credenciales_o_movimiento(self):
        self.assertTrue(all(r.agrupar_por is None for r in RULES if r.id in {'WLH-001','WLH-002','WLH-003','WLH-004'}))

    def test_cache_procesos_respeta_subconjuntos_predicados_y_siguiente_analisis(self):
        recibidos=[]
        def recoger(events,cfg):
            recibidos.append([p.image for p in base._processes(events)])
            return []
        rules=[Rule('A','','low',(),'',recoger,frozenset({1,4688})),
               Rule('B','','low',(),'',recoger,frozenset({1})),
               Rule('C','','low',(),'',recoger,frozenset({1,4688}),lambda e:e.event_id==4688)]
        events=[sysmon(0,'a.exe','a'),ev(4688,NewProcessName='b.exe')]
        with patch.object(base,'RULES',rules):
            run_rules(events)
            events[0].data['Image']='otro.exe'
            run_rules(events)
        self.assertEqual(recibidos,[['a.exe','b.exe'],['a.exe'],['b.exe'],['otro.exe','b.exe'],['otro.exe'],['b.exe']])


class CargaYSalida(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)

    def test_jsonl_streaming_fechas_y_estadisticas(self):
        p = self.folder/"eventos.jsonl"
        p.write_text("\n".join(json.dumps({"EventID":i,"TimeCreated":date}) for i,date in [
            (4634,"2026-11-03T09:00:00Z"),(4720,"2026-11-03T09:00:00Z"),
            (4720,"2026-11-03T10:00:00Z")]),encoding="utf-8")
        with patch.object(Path,"read_bytes",side_effect=AssertionError("lectura completa")):
            loaded = parsers.load_events([p],plan=planificar(),desde=BASE,hasta=BASE)
        self.assertEqual(len(loaded.events),1)
        self.assertEqual((loaded.leidos,loaded.descartados),(3,2))
        self.assertGreater(loaded.segundos,0)

    def test_json_array_admite_seleccion(self):
        p=self.folder/"eventos.json"
        p.write_text(json.dumps([{"EventID":4634,"TimeCreated":"2026-11-03"},
                                 {"EventID":4720,"TimeCreated":"2026-11-03"}]),encoding="utf-8")
        self.assertEqual([e.event_id for e in parsers.load_events([p],plan=planificar()).events],[4720])

    def test_xml_doctype_tardio_no_emite_ningun_evento(self):
        p=self.folder/"mal.xml"
        p.write_text(xml_event()*500+'<!DOCTYPE x>',encoding="utf-8")
        result=parsers.load_events([p])
        self.assertEqual(result.events,[])
        self.assertIn("DOCTYPE",result.warnings[0])

    def test_procesos_1_y_2_mismo_resultado(self):
        paths=[]
        for name in ("a.jsonl","b.jsonl"):
            p=self.folder/name
            p.write_text(SAMPLE.read_text(encoding="utf-8"),encoding="utf-8")
            paths.append(p)
        one=parsers.load_events(paths,plan=planificar(),procesos=1)
        many=parsers.load_events(paths,plan=planificar(),procesos=2)
        self.assertEqual(one.events,many.events)
        self.assertEqual([f.to_dict() for f in run_rules(one.events)],
                         [f.to_dict() for f in run_rules(many.events)])
        self.assertEqual(one.leidos,many.leidos)

    def test_fechas_relativas_y_validacion_cli(self):
        self.assertEqual(parsers.limite_temporal("24h",BASE),BASE-timedelta(days=1))
        self.assertEqual(parsers.limite_temporal("7d",BASE),BASE-timedelta(days=7))
        for options in [("--procesos","0"),("--desde","ayer"),("--desde","2026-12-01","--hasta","2026-01-01")]:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["analyze",str(SAMPLE),*options]),2)

    def test_html_limita_por_regla_json_completo(self):
        import csv
        findings=run_rules([ev(4720,n,TargetUserName=str(n)) for n in range(205)])
        stats=Stats(205,1)
        page=render_html(findings,stats)
        self.assertEqual(page.count('<article class="finding"'),200)
        self.assertIn("y 5 más",page)
        self.assertEqual(len(json.loads(render_json(findings,stats))["findings"]),205)
        self.assertEqual(len(list(csv.reader(io.StringIO(render_csv(findings,stats))))),206)

    def test_csv_no_ejecuta_formulas_de_logs(self):
        import csv
        findings=run_rules([ev(7045,computer="=SUM(A1:A2)",ServiceName="prueba",ImagePath="normal.exe")],only={"WLH-006"})
        rows=list(csv.reader(io.StringIO(render_csv(findings,Stats(1,1)))))
        self.assertEqual(rows[1][7],"'=SUM(A1:A2)")


if __name__ == "__main__":
    unittest.main()
