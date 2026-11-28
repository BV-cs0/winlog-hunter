"""Casos sintéticos del bloque de detección de procesos, sin datos del benchmark."""

import unittest

from helpers import ev, sysmon
from winlog_hunter.rules import RULES, run_rules


SYSTEM = "C:\\Windows\\System32\\"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def hits(rule_id, events):
    return run_rules(events, only={rule_id})


class UacRules(unittest.TestCase):
    def test_registry_hijacks(self):
        keys = [
            r"HKCU\Software\Classes\ms-settings\shell\open\command\DelegateExecute",
            r"HKU\S-1-5-21-123\Software\Classes\mscfile\shell\open\command\(Default)",
            r"HKU\S-1-5-21-456_Classes\ms-settings\shell\open\command\DelegateExecute",
            r"HKCU\Software\Classes\Folder\shell\open\command",
            r"HKCU\Environment\windir", r"HKCU\Environment\SystemRoot",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe\(Default)",
        ]
        for key in keys:
            with self.subTest(key=key):
                self.assertTrue(hits("WLH-022", [ev(13, channel=CHANNEL, TargetObject=key, Details="cmd.exe")]))
        for key in (r"HKLM\Software\Classes\mscfile\shell\open\command",
                    r"HKCU\Environment\Path", r"HKCU\Software\Classes\txtfile\shell\open\command"):
            with self.subTest(key=key):
                self.assertFalse(hits("WLH-022", [ev(13, channel=CHANNEL, TargetObject=key)]))
        self.assertFalse(hits("WLH-022", [ev(12, channel=CHANNEL, TargetObject=keys[0], EventType="DeleteValue")]))
        self.assertFalse(hits("WLH-022", [ev(13, TargetObject=keys[0])]))

    def test_autoelevated_children_and_4688(self):
        for make in (
            lambda: sysmon(0, SYSTEM + "cmd.exe", "cmd /c whoami", SYSTEM + "fodhelper.exe"),
            lambda: ev(4688, NewProcessName=SYSTEM + "cmd.exe", ParentProcessName=SYSTEM + "eventvwr.exe"),
        ):
            self.assertEqual(hits("WLH-022", [make()])[0].severity, "high")
        self.assertFalse(hits("WLH-022", [sysmon(0, SYSTEM + "mmc.exe", "mmc eventvwr.msc", SYSTEM + "eventvwr.exe")]))
        self.assertFalse(hits("WLH-022", [sysmon(0, SYSTEM + "cmd.exe", "cmd", r"C:\Tools\fodhelper.exe")]))
        suspicious = sysmon(0, SYSTEM + "cmd.exe", "cmd", SYSTEM + "mmc.exe")
        self.assertFalse(hits("WLH-022", [suspicious]))
        suspicious.data["ParentCommandLine"] = r"mmc.exe C:\Users\Public\console.msc"
        self.assertTrue(hits("WLH-022", [suspicious]))

    def test_dll_and_file_signals(self):
        for data in (
            dict(Image=SYSTEM + r"sysprep\sysprep.exe", ImageLoaded=r"C:\Users\Public\version.dll", Signed="true"),
            dict(Image=SYSTEM + "cliconfg.exe", ImageLoaded=SYSTEM + "version.dll", Signed="false"),
        ):
            self.assertTrue(hits("WLH-022", [ev(7, channel=CHANNEL, **data)]))
        self.assertFalse(hits("WLH-022", [ev(7, channel=CHANNEL, Image=SYSTEM + "cliconfg.exe", ImageLoaded=SYSTEM + "version.dll", Signed="true")]))
        self.assertFalse(hits("WLH-022", [ev(7, channel=CHANNEL, Image=SYSTEM + "cliconfg.exe", ImageLoaded=SYSTEM + "version.dll")]))
        for target in (SYSTEM + r"sysprep\version.dll", r"D:\Windows \System32\version.dll"):
            self.assertTrue(hits("WLH-022", [ev(11, channel=CHANNEL, Image=SYSTEM + "cmd.exe", TargetFilename=target)]))
        self.assertFalse(hits("WLH-022", [ev(11, channel=CHANNEL, Image=SYSTEM + "msiexec.exe", TargetFilename=SYSTEM + r"sysprep\version.dll")]))
        self.assertFalse(hits("WLH-022", [ev(11, channel=CHANNEL, Image=SYSTEM + "cmd.exe", TargetFilename=SYSTEM + r"sysprep\setup.log")]))

    def test_cmstp(self):
        self.assertEqual(hits("WLH-022", [sysmon(0, SYSTEM + "cmstp.exe", "cmstp /s C:\\Temp\\profile.inf")])[0].severity, "high")
        self.assertFalse(hits("WLH-022", [sysmon(0, SYSTEM + "cmstp.exe", "cmstp /s")]))
        self.assertFalse(hits("WLH-022", [sysmon(0, SYSTEM + "cmstp.exe", "cmstp profile.inf")]))


class LolbinRules(unittest.TestCase):
    def test_new_arguments(self):
        examples = {
            "pcalua.exe": "pcalua -a C:\\Tools\\app.exe",
            "msxsl.exe": "msxsl data.xml transform.xsl",
            "desktopimgdownldr.exe": "desktopimgdownldr /lockscreenurl:https://example.org/a.png",
            "ftp.exe": "ftp -s:commands.txt", "hh.exe": "hh https://example.org/manual.chm",
            "wuauclt.exe": "wuauclt /UpdateDeploymentProvider C:\\Temp\\a.dll /RunHandlerComServer",
            "vshadow.exe": "vshadow -exec=cmd.exe C:",
            "msiexec.exe": "msiexec /y C:\\Tools\\module.dll",
            "wmic.exe": 'wmic os get /format:"https://example.org/style.xsl"',
            "control.exe": 'control "C:\\Program Files\\Tool\\panel.cpl"',
        }
        for image, command in examples.items():
            with self.subTest(image=image):
                self.assertTrue(hits("WLH-011", [sysmon(0, SYSTEM + image, command)]))
                self.assertFalse(hits("WLH-011", [sysmon(0, SYSTEM + image, image + " /?")]))
        for command in ("rundll32 advpack.dll,LaunchINFSection setup.inf,DefaultInstall",
                        "rundll32 zipfldr.dll,RouteTheCall file.zip", "rundll32 pcwutl.dll,LaunchApplication app.exe",
                        "rundll32 shell32.dll,ShellExec_RunDLL app.exe", "rundll32 shell32.dll,Control_RunDLL app.cpl"):
            self.assertTrue(hits("WLH-011", [sysmon(0, SYSTEM + "rundll32.exe", command)]))
        for command in ("msiexec /i https://example.org/app.msi", "msiexec /y module.dll"):
            self.assertTrue(hits("WLH-011", [sysmon(0, SYSTEM + "msiexec.exe", command)]))
        self.assertTrue(hits("WLH-011", [sysmon(0, r"C:\Tools\msxsl.exe", "msxsl source.dat style.dat")]))
        self.assertTrue(hits("WLH-011", [sysmon(0, SYSTEM + "cmd.exe", "cmd", r"C:\Tools\msxsl.exe")]))
        event = sysmon(0, SYSTEM + "cmd.exe", "cmd", SYSTEM + "wuauclt.exe")
        self.assertFalse(hits("WLH-011", [event]))
        event.data["ParentCommandLine"] = "wuauclt /RunHandlerComServer"
        self.assertTrue(hits("WLH-011", [event]))
        self.assertFalse(hits("WLH-011", [sysmon(0, SYSTEM + "control.exe", 'control "C:\\Windows\\System32\\appwiz.cpl"')]))
        self.assertFalse(hits("WLH-011", [sysmon(0, SYSTEM + "wmic.exe", "wmic os get /format:table")]))
        self.assertTrue(hits("WLH-011", [sysmon(0, SYSTEM + "cmd.exe", "cmd", r"C:\Windows\hh.exe")]))


class ScriptEngineRules(unittest.TestCase):
    def test_forced_engine_on_non_script(self):
        bad = sysmon(0, SYSTEM + "wscript.exe", r'"wscript.exe" /E:vbs c:\windows\temp\icon.ico')
        self.assertTrue(hits("WLH-011", [bad]))
        for command in (r"wscript.exe /E:vbs C:\scripts\inventario.vbs", r"cscript //nologo C:\scripts\backup.js"):
            self.assertFalse(hits("WLH-011", [sysmon(0, SYSTEM + "wscript.exe", command)]))


class MasqueradingRules(unittest.TestCase):
    def test_original_name_and_accessibility(self):
        renamed = sysmon(0, r"C:\Tools\support.exe", "support")
        renamed.data["OriginalFileName"] = "PowerShell.EXE"
        self.assertEqual(hits("WLH-023", [renamed])[0].severity, "medium")
        renamed.data["Image"] = SYSTEM + "sethc.exe"
        self.assertEqual(hits("WLH-023", [renamed])[0].severity, "high")
        renamed.data.update(Image=SYSTEM + "powershell.exe")
        self.assertFalse(hits("WLH-023", [renamed]))
        renamed.data.update(Image=r"C:\Tools\PsExec64.exe", OriginalFileName="psexec.c")
        self.assertFalse(hits("WLH-023", [renamed]))
        renamed.data.update(Image=r"C:\Tools\procdump64.exe", OriginalFileName="procdump")
        self.assertFalse(hits("WLH-023", [renamed]))
        renamed.data.update(Image=r"C:\Tools\custom.exe", OriginalFileName="custom-original.exe")
        self.assertFalse(hits("WLH-023", [renamed]))

    def test_system_paths(self):
        for image in (r"C:\Users\Public\svchost.exe", r"C:\Temp\explorer.exe", r"C:\Windows \System32\lsass.exe"):
            self.assertEqual(hits("WLH-023", [sysmon(0, image, image)])[0].severity, "high")
        for image in (SYSTEM + "svchost.exe", r"C:\Windows\explorer.exe", r"D:\Windows\SysWOW64\wermgr.exe",
                      r"C:\Windows\SysWOW64\explorer.exe"):
            self.assertFalse(hits("WLH-023", [sysmon(0, image, image)]))
        self.assertTrue(hits("WLH-023", [ev(4688, NewProcessName=r"C:\Temp\lsass.exe")]))
        self.assertFalse(hits("WLH-023", [sysmon(0, r"C:\Tools\support.exe", "support")]))


class ServerShellRules(unittest.TestCase):
    def test_server_shell_and_legitimate_child(self):
        for parent in ("w3wp.exe", "httpd.exe", "sqlservr.exe", "spoolsv.exe", "msiexec.exe", "smss.exe"):
            with self.subTest(parent=parent):
                self.assertTrue(hits("WLH-024", [sysmon(0, SYSTEM + "cmd.exe", "cmd /c whoami", SYSTEM + parent)]))
                self.assertFalse(hits("WLH-024", [sysmon(0, SYSTEM + "conhost.exe", "conhost", SYSTEM + parent)]))
        self.assertFalse(hits("WLH-024", [sysmon(0, SYSTEM + "autochk.exe", "autochk", SYSTEM + "smss.exe")]))

    def test_dcom_and_no_overlap(self):
        event = sysmon(0, SYSTEM + "mmc.exe", "mmc -Embedding", SYSTEM + "svchost.exe")
        self.assertEqual(hits("WLH-024", [event])[0].mitre, ["T1021.003"])
        event.data["CommandLine"] = "mmc eventvwr.msc"
        self.assertFalse(hits("WLH-024", [event]))
        event = sysmon(0, SYSTEM + "cmd.exe", "cmd", r"C:\Windows\explorer.exe")
        self.assertFalse(hits("WLH-024", [event]))
        event.data["ParentCommandLine"] = "explorer.exe /Embedding"
        self.assertTrue(hits("WLH-024", [event]))
        # Ventana normal del explorador abierta por Windows: abrir una consola desde ella es legítimo.
        event.data["ParentCommandLine"] = "explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding"
        self.assertFalse(hits("WLH-024", [event]))
        factory = sysmon(0, r"C:\Windows\explorer.exe",
                         "explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding", SYSTEM + "svchost.exe")
        self.assertFalse(hits("WLH-024", [factory]))
        installer = sysmon(0, SYSTEM + "cmd.exe", "cmd /c accion.bat", SYSTEM + "msiexec.exe")
        self.assertEqual(hits("WLH-024", [installer])[0].severity, "low")
        for parent, rule_id in (("excel.exe", "WLH-012"), ("wsmprovhost.exe", "WLH-018"), ("wmiprvse.exe", "WLH-018")):
            event = sysmon(0, SYSTEM + "cmd.exe", "cmd", SYSTEM + parent)
            event.data["ParentCommandLine"] = parent + " -Embedding"
            found = {f.rule_id for f in run_rules([event])}
            self.assertIn(rule_id, found)
            self.assertNotIn("WLH-024", found)


class DefenseCommandRules(unittest.TestCase):
    def test_destructive_and_benign_commands(self):
        cases = [
            ("vssadmin.exe", "delete shadows /all", "list shadows"),
            ("wmic.exe", "shadowcopy delete", "shadowcopy list"),
            ("wbadmin.exe", "delete catalog -quiet", "get versions"),
            ("bcdedit.exe", "/set {default} recoveryenabled no", "/set {default} recoveryenabled yes"),
            ("bcdedit.exe", "/set {default} bootstatuspolicy ignoreallfailures", "/set {default} bootstatuspolicy displayallfailures"),
            ("wevtutil.exe", "cl Security", "gl Security"),
            ("wevtutil.exe", "sl Security /e:false", "sl Security /e:true"),
            ("auditpol.exe", "/set /category:* /success:disable", "/set /category:* /success:enable"),
            ("auditpol.exe", "/clear", "/get /category:*"),
            ("netsh.exe", "advfirewall set allprofiles state off", "advfirewall set allprofiles state on"),
            ("netsh.exe", "interface portproxy add v4tov4 listenport=445", "interface portproxy show all"),
            ("powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring $true", "Set-MpPreference -DisableRealtimeMonitoring $false"),
            ("powershell.exe", "Add-MpPreference -ExclusionPath C:\\Tools", "Get-MpPreference"),
            ("attrib.exe", "+h +s document.txt", "-h -s document.txt"),
            ("net.exe", "stop eventlog", "stop spooler"),
            ("sc.exe", "config eventlog start= disabled", "config eventlog start= auto"),
            ("taskkill.exe", '/fi "SERVICES eq EventLog" /f', "/im svchost.exe /f"),
        ]
        for image, bad, good in cases:
            with self.subTest(image=image, command=bad):
                self.assertTrue(hits("WLH-025", [sysmon(0, SYSTEM + image, image + " " + bad)]))
                self.assertFalse(hits("WLH-025", [sysmon(0, SYSTEM + image, image + " " + good)]))
        self.assertTrue(hits("WLH-025", [sysmon(0, SYSTEM + "cmd.exe", "cmd /c net stop eventlog")]))
        self.assertFalse(hits("WLH-025", [sysmon(0, SYSTEM + "cmd.exe", 'cmd /c echo "net stop eventlog"')]))
        self.assertFalse(hits("WLH-025", [sysmon(0, SYSTEM + "notepad.exe", 'notepad "vssadmin delete shadows"')]))
        self.assertTrue(hits("WLH-025", [ev(4688, NewProcessName=SYSTEM + "vssadmin.exe", CommandLine="vssadmin delete shadows /all")]))

    def test_taskkill_requires_eventlog_identity(self):
        service = sysmon(0, SYSTEM + "svchost.exe", "svchost -k LocalServiceNetworkRestricted -s EventLog")
        service.data["ProcessId"] = "412"
        kill = sysmon(10, SYSTEM + "taskkill.exe", "taskkill /pid 412 /f")
        self.assertFalse(hits("WLH-025", [kill]))
        self.assertTrue(hits("WLH-025", [service, kill]))
        reused = sysmon(5, SYSTEM + "notepad.exe", "notepad")
        reused.data["ProcessId"] = "412"
        self.assertFalse(hits("WLH-025", [service, reused, kill]))
        service.data["ProcessId"] = "0x19c"
        self.assertTrue(hits("WLH-025", [service, kill]))
        service.computer = "OTHER"
        self.assertFalse(hits("WLH-025", [service, kill]))

    def test_registration_order(self):
        self.assertEqual([r.id for r in RULES], sorted(r.id for r in RULES))


if __name__ == "__main__":
    unittest.main()
