import unittest

from helpers import ev, sysmon
from winlog_hunter import local
from winlog_hunter.parsers import consultas_xpath
from winlog_hunter.rules import planificar, run_rules

SYSMON = "Microsoft-Windows-Sysmon/Operational"
WINRM = "Microsoft-Windows-WinRM/Operational"
RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
CORE = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
SHARES = "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Shares\\"
TSCLIENT = r"\\tsclient\C\programa.exe"


def sm(evento, segundos=0, **datos):
    return ev(evento, segundos, channel=SYSMON, **datos)


def hallazgos(regla, *eventos):
    return run_rules(eventos, only={f"WLH-{regla:03}"})


class MovimientoRemoto(unittest.TestCase):
    def test_padre_4688_anterior_del_mismo_equipo(self):
        padre = ev(4688, NewProcessName=r"C:\Windows\System32\wbem\WmiPrvSE.exe", NewProcessId="0xae8")
        hijo = ev(4688, 1, NewProcessName=r"C:\Windows\System32\calc.exe", ProcessId="0xAE8")
        self.assertTrue(hallazgos(18, hijo, padre))
        self.assertFalse(hallazgos(18, hijo))
        hijo.data["ParentProcessName"] = "explorer.exe"
        self.assertFalse(hallazgos(18, padre, hijo))

    def test_registro_eventos(self):
        pipe = sm(18, PipeName=r"\eventlog", Image="System")
        fallo = sm(1, 1, Image="WerFault.exe", CommandLine="WerFault.exe -u -p 123",
                   ParentImage="svchost.exe", ParentCommandLine="svchost -k LocalServiceNetworkRestricted")
        self.assertFalse(hallazgos(37, pipe))
        self.assertFalse(hallazgos(37, fallo))
        self.assertTrue(hallazgos(37, pipe, fallo))
        self.assertFalse(hallazgos(37, sm(18, -119, **pipe.data), fallo))
        self.assertFalse(hallazgos(37, ev(18, channel=SYSMON, computer="OTRO", **pipe.data), fallo))
        fallo.data["ParentCommandLine"] = "svchost.exe -s EVENTLOG"
        self.assertTrue(hallazgos(37, fallo))
        for evento in (7031, 7034):
            with self.subTest(evento=evento):
                self.assertTrue(hallazgos(37, ev(evento, channel="System", param1="Registro de eventos de Windows")))
        self.assertFalse(hallazgos(37, ev(7036, channel="System", param1="Windows Event Log", param2="running")))
        # Deshabilitarlo (7040) lo trata WLH-034; aquí no debe repetirse
        self.assertFalse(hallazgos(37, ev(7040, channel="System", param1="Windows Event Log", param3="disabled")))

    def test_dcom(self):
        proceso = sysmon(0, "mshta.exe", "mshta.exe -Embedding", "svchost.exe")
        self.assertTrue(hallazgos(38, proceso))
        proceso.data["ParentCommandLine"] = "svchost -k DcomLaunch"
        self.assertTrue(hallazgos(38, proceso))
        proceso.data["ParentCommandLine"] = "svchost -k netsvcs"
        self.assertFalse(hallazgos(38, proceso))
        self.assertTrue(hallazgos(38, ev(4688, NewProcessName="mmc.exe", ParentProcessName="svchost.exe",
                                        CommandLine="mmc.exe -Embedding")))
        self.assertTrue(hallazgos(38, sm(3, Image="explorer.exe", Initiated="false", DestinationIp="192.168.1.1")))
        self.assertFalse(hallazgos(38, sm(3, Image="explorer.exe", Initiated="false", DestinationIp="::1")))
        datos = dict(param2="Remote", param3="Launch", param5="{49B2791A-B1AE-4C90-9B8E-E860BA07F889}",
                     param6="DOM", param7="ana", param9="192.168.1.1")
        aviso = ev(10016, channel="System", provider="Microsoft-Windows-DistributedCOM", **datos)
        resultado, = hallazgos(38, aviso)
        self.assertEqual(resultado.severity, "medium")
        self.assertEqual(resultado.evidence["usuario"], r"DOM\ana")
        aviso.data["param2"] = "Local"
        self.assertFalse(hallazgos(38, aviso))
        aviso.data.update(param2="Remote", param5="{otro}")
        self.assertFalse(hallazgos(38, aviso))
        rpc = sm(3, Image="pwsh.exe", Initiated="true", DestinationIp="192.168.1.1", DestinationPort="135")
        self.assertEqual(hallazgos(38, rpc)[0].severity, "medium")
        self.assertFalse(hallazgos(31, rpc))

    def test_winrm(self):
        for imagen, severidad in (("hostname.exe", "medium"), (r"C:\Temp\app.exe", "medium"), ("notepad.exe", "low")):
            self.assertEqual(hallazgos(39, sysmon(0, imagen, imagen, "wsmprovhost.exe"))[0].severity, severidad)
        self.assertFalse(hallazgos(39, sysmon(0, "cmd.exe", "cmd", "winrshost.exe")))
        self.assertFalse(hallazgos(39, sysmon(0, "hostname.exe", "hostname", "explorer.exe")))
        shell = ev(91, channel=WINRM, username="ANA")
        autenticacion = ev(169, 5, channel=WINRM, username="ana", authenticationMechanism="Kerberos")
        self.assertTrue(hallazgos(39, shell))
        self.assertTrue(hallazgos(39, autenticacion))
        resultado, = hallazgos(39, shell, autenticacion)
        self.assertEqual(resultado.severity, "low")
        self.assertEqual(resultado.evidence["autenticación"], ["Kerberos"])

    def test_rdp(self):
        for evento in (
            ev(4624, LogonType="10", IpAddress="127.0.0.1"),
            ev(1149, channel=RCM, Param1="ana", Param2="DOM", Param3="::1"),
            ev(131, channel=CORE, ClientIP="[::1]:59407"),
            ev(131, channel=CORE, ClientIP="127.0.0.1:52202"),
            sm(1, Image=TSCLIENT),
            ev(4688, NewProcessName=TSCLIENT),
        ):
            with self.subTest(evento=evento):
                self.assertEqual(hallazgos(40, evento)[0].severity, "high")
        self.assertFalse(hallazgos(40, ev(4624, LogonType="10", IpAddress="10.1.1.1")))
        self.assertFalse(hallazgos(40, ev(4624, LogonType="3", IpAddress="127.0.0.1")))
        mru = sm(13, TargetObject=r"HKU\SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a", Details=TSCLIENT)
        self.assertEqual(hallazgos(40, mru)[0].severity, "medium")
        for imagen, firmado, severidad in (
            (r"C:\ProgramData\ejemplo.exe", "true", "high"),
            (r"C:\Herramientas\ejemplo.exe", "false", "high"),
            (r"C:\Program Files\Vendor\ejemplo.exe", "true", "low"),
            (r"C:\Program Files\Vendor\msrdcw.exe", "true", None),
        ):
            resultados = hallazgos(40, sm(7, Image=imagen, Signed=firmado, ImageLoaded="mstscax.dll"))
            self.assertEqual([h.severity for h in resultados], [severidad] if severidad else [])

    def test_tarea_asociada_a_sesion_remota(self):
        sesion = ev(4624, LogonType="3", TargetLogonId="0x100", IpAddress="10.0.0.5")
        for evento in (4698, 4702):
            tarea = ev(evento, 1, SubjectLogonId="0x0100", TaskName=r"\Copia", SubjectUserName="ana")
            self.assertEqual(hallazgos(41, sesion, tarea)[0].severity, "high")
            self.assertFalse(hallazgos(41, tarea))
            self.assertFalse(hallazgos(41, sesion, ev(evento, 1, computer="OTRO", **tarea.data)))
        sesion.data["IpAddress"] = "127.0.0.1"
        self.assertFalse(hallazgos(41, sesion, tarea))

    def test_copias_servicios_y_recursos(self):
        self.assertTrue(hallazgos(41, sm(11, Image="System", TargetFilename=r"C:\Windows\Temp\programa.ps1")))
        self.assertFalse(hallazgos(41, sm(11, Image="System", TargetFilename=r"C:\Windows-old\programa.ps1")))
        self.assertFalse(hallazgos(41, sm(11, Image="System", TargetFilename=r"C:\Windows\Temp\notas.txt")))
        for nombre in ("psexesvc.exe", "paexec-123.exe", "remcomsvc.exe", "csexecsvc.exe"):
            self.assertTrue(hallazgos(41, sysmon(0, nombre, nombre, "services.exe")))
            self.assertFalse(hallazgos(41, sysmon(0, nombre, nombre, "explorer.exe")))
        for evento in (sm(13, TargetObject=SHARES + "Docs"), ev(5142, ShareName=r"\\*\Docs")):
            self.assertEqual(hallazgos(41, evento)[0].severity, "medium")
        self.assertFalse(hallazgos(41, sm(13, TargetObject=SHARES + r"Security\Docs")))

    def test_credenciales_explicitas_y_sql(self):
        credenciales = ev(4648, ProcessName="wmic.exe", TargetServerName="otro.dominio")
        self.assertEqual(hallazgos(41, credenciales)[0].severity, "medium")
        for destino in ("HOST.dominio", "localhost", "127.0.0.1"):
            credenciales.data["TargetServerName"] = destino
            self.assertFalse(hallazgos(41, credenciales))
        def sql(evento, **datos):
            return ev(evento, channel="Application", provider="MSSQL$INSTANCIA", **datos)
        self.assertEqual(hallazgos(41, sql(15281, Data0="xp_cmdshell"))[0].severity, "medium")
        self.assertEqual(hallazgos(41, sql(15457, Data0="xp_cmdshell", Data1="0", Data2="1"))[0].severity, "high")
        self.assertFalse(hallazgos(41, sql(15457, Data0="xp_cmdshell", Data1="1", Data2="0")))
        self.assertFalse(hallazgos(41, sql(15281, Data0="otra opción")))

    def test_bind_shell_y_ntds(self):
        conexion = sm(3, Image="ncat.exe", Initiated="false", SourcePort="4444", DestinationIp="10.1.1.1")
        self.assertEqual(hallazgos(31, conexion)[0].severity, "high")
        for puerto in ("5985", "5986"):
            conexion.data["SourcePort"] = puerto
            self.assertFalse(hallazgos(31, conexion))
        clave = r"HKLM\System\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt"
        resultado, = hallazgos(19, sm(13, TargetObject=clave, Details=r"\\equipo\recurso\modulo.dll"))
        self.assertIn("UNC", resultado.summary)
        self.assertEqual(resultado.severity, "high")
        self.assertFalse(hallazgos(19, sm(13, TargetObject=clave + "Otro")))

    def test_canales_planificados_y_consultas(self):
        plan = planificar()
        consultas = " ".join(consultas_xpath(plan.ids))
        for canal, evento in ((WINRM, 91), (WINRM, 169), (RCM, 1149), (CORE, 131)):
            self.assertIn(canal, local.LOGS)
            self.assertIn(canal, local.AUDIT_LOG_SIZES)
            self.assertTrue(plan.acepta(ev(evento, channel=canal)))
            self.assertIn(f"EventID={evento}", consultas)
