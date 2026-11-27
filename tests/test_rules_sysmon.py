"""Telemetría sintética del bloque 1b y actividades normales de un puesto de oficina."""

import unittest

from helpers import ev, sysmon
from winlog_hunter.rules import run_rules


CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSTEM = "C:\\Windows\\System32\\"
USER = "C:\\Users\\operador\\"


def sm(event_id, **data):
    return ev(event_id, channel=CHANNEL, **data)


def hits(rule_id, *events):
    return run_rules(events, only={rule_id})


class InjectionRules(unittest.TestCase):
    def test_remote_thread_and_normal_windows_sources(self):
        bad = sm(8, SourceImage=USER + "Downloads\\loader.exe", TargetImage=SYSTEM + "notepad.exe")
        self.assertEqual(hits("WLH-026", bad)[0].severity, "high")
        for source, target in (
            (SYSTEM + "csrss.exe", SYSTEM + "conhost.exe"),
            (SYSTEM + "svchost.exe", SYSTEM + "services.exe"),
            (r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2401\MsMpEng.exe", SYSTEM + "notepad.exe"),
            (r"C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe", USER + "source\\repos\\app.exe"),
            (r"C:\Windows\Sysmon64.exe", SYSTEM + "services.exe"),
            (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            (USER + r"AppData\Local\Google\Chrome\Application\chrome.exe", USER + r"AppData\Local\Google\Chrome\Application\chrome.exe"),
        ):
            with self.subTest(source=source):
                self.assertFalse(hits("WLH-026", sm(8, SourceImage=source, TargetImage=target)))
        self.assertTrue(hits("WLH-026", sm(8, SourceImage=USER + "MsMpEng.exe", TargetImage=SYSTEM + "notepad.exe")))
        self.assertTrue(hits("WLH-026", sm(8, SourceImage=r"C:\Program Files\Google\Chrome\Application\chrome.exe", TargetImage=SYSTEM + "notepad.exe")))

    def test_kernel_thread_between_windows_processes_is_routine(self):
        # dwm.exe -> csrss.exe con dirección del kernel: lo hace Windows en cualquier PC.
        kernel = dict(SourceImage=r"C:\Windows\System32\dwm.exe", TargetImage=r"C:\Windows\System32\csrss.exe")
        self.assertFalse(hits("WLH-026", sm(8, StartAddress="0xFFFFF8016E65D2E0", **kernel)))
        # Con una dirección de usuario, o desde fuera de System32, sigue siendo sospechoso.
        self.assertTrue(hits("WLH-026", sm(8, StartAddress="0x00007FF6A1B20000", **kernel)))
        self.assertTrue(hits("WLH-026", sm(8, SourceImage=USER + "Downloads\\loader.exe", TargetImage=SYSTEM + "csrss.exe",
                                           StartAddress="0xFFFFF8016E65D2E0")))

    def test_access_requires_real_injection_rights(self):
        for mask in ("0x1F0FFF", "0x1FFFFF", "0x143A", "0x1F3FFF"):
            self.assertEqual(hits("WLH-026", sm(10, SourceImage=USER + "loader.exe", TargetImage=SYSTEM + "notepad.exe", GrantedAccess=mask))[0].severity, "medium")
        # Inventario de procesos y suspensión no son escritura de memoria ni creación de hilos.
        for mask in ("0x1000", "0x0800", "0x10", "0x20", "malformado", ""):
            self.assertFalse(hits("WLH-026", sm(10, SourceImage=USER + "inventory.exe", TargetImage=SYSTEM + "notepad.exe", GrantedAccess=mask)))
        self.assertFalse(hits("WLH-026", sm(10, SourceImage=r"C:\Program Files\Microsoft Visual Studio\Common7\IDE\devenv.exe", TargetImage=USER + "app.exe", GrantedAccess="0x1fffff")))

    def test_unknown_trace_tampering_and_lsass_ownership(self):
        event = sm(10, SourceImage=SYSTEM + "rundll32.exe", TargetImage=SYSTEM + "notepad.exe", GrantedAccess="0x143a", CallTrace="ntdll.dll+123|UNKNOWN(00007FF01234)")
        self.assertEqual(hits("WLH-026", event)[0].severity, "high")
        event.data["GrantedAccess"] = "0x10"
        self.assertEqual(hits("WLH-026", event)[0].severity, "low")
        normal = sm(10, SourceImage=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2401\MsMpEng.exe", TargetImage=SYSTEM + "notepad.exe", GrantedAccess="0x1fffff", CallTrace="UNKNOWN(00007FF01234)")
        self.assertFalse(hits("WLH-026", normal))
        normal.data.update(SourceImage=USER + "self.exe", TargetImage=USER + "self.exe", SourceProcessGUID="{ABC}", TargetProcessGUID="{abc}")
        self.assertFalse(hits("WLH-026", normal))
        query = sm(10, SourceImage=r"C:\Windows\explorer.exe", TargetImage=r"C:\Program Files\Vendor\app.exe", GrantedAccess="0x1410", CallTrace="appresolver.dll+123|UNKNOWN(00007FF01234)")
        self.assertFalse(hits("WLH-026", query))
        query.data["GrantedAccess"] = "0x143a"
        self.assertTrue(hits("WLH-026", query))
        event.data["TargetImage"] = SYSTEM + "lsass.exe"
        self.assertFalse(hits("WLH-026", event))
        self.assertTrue(hits("WLH-013", event))
        self.assertEqual(hits("WLH-026", sm(25, Image=USER + "modified.exe", Type="Image is replaced"))[0].severity, "high")
        self.assertFalse(hits("WLH-026", ev(25, channel="Application", Image=USER + "app.exe")))


class DllRules(unittest.TestCase):
    def test_system_loader_and_normal_unsigned_application_libraries(self):
        self.assertTrue(hits("WLH-027", sm(7, Image=SYSTEM + "rundll32.exe", ImageLoaded=USER + "Downloads\\plugin.dll", Signed="false")))
        for image, dll, signed in (
            (r"C:\Program Files\Vendor\App\app.exe", r"C:\Program Files\Vendor\App\plugin.dll", "false"),
            (SYSTEM + "rundll32.exe", SYSTEM + "version.dll", "true"),
            (SYSTEM + "rundll32.exe", USER + "plugin.dll", "true"),
            (SYSTEM + "rundll32.exe", USER + "plugin.dll", ""),
            (USER + "AppData\\Local\\Programs\\Vendor\\app.exe", USER + "AppData\\Local\\Programs\\Vendor\\version.dll", "false"),
            (r"C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe", USER + "symbols\\dbghelp.dll", "false"),
        ):
            with self.subTest(image=image, dll=dll):
                self.assertFalse(hits("WLH-027", sm(7, Image=image, ImageLoaded=dll, Signed=signed)))

    def test_specific_hijack_and_untrusted_prefix(self):
        self.assertEqual(hits("WLH-027", sm(7, Image=USER + "Documents\\winword.exe", ImageLoaded=USER + "Documents\\wwlib.dll", Signed="false"))[0].severity, "high")
        self.assertTrue(hits("WLH-027", sm(7, Image=SYSTEM + "rundll32.exe", ImageLoaded=r"C:\Program Files-old\plugin.dll", Signed="false")))
        # Company pertenece a la DLL: no se interpreta como firma del cargador.
        self.assertFalse(hits("WLH-027", sm(7, Image=USER + "app.exe", ImageLoaded=USER + "plugin.dll", Signed="false", Company="Microsoft Corporation")))


class PipeRules(unittest.TestCase):
    def test_known_names_and_legitimate_windows_pipes(self):
        for pipe in (r"\msagent_123abc", r"\postex_42", r"\status_ab12", r"\MSSE-123-server", r"\xyz\pipe\spoolss"):
            self.assertEqual(hits("WLH-028", sm(17, PipeName=pipe, Image=USER + "agent.exe"))[0].severity, "high")
        self.assertEqual(hits("WLH-028", sm(18, PipeName=r"\PSEXESVC", Image=SYSTEM + "services.exe"))[0].severity, "low")
        self.assertTrue(hits("WLH-028", sm(17, PipeName=r"\kekeo_tsssp_endpoint", Image=USER + "agent.exe")))
        for pipe, image, event_id in (
            (r"\spoolss", SYSTEM + "spoolsv.exe", 17),
            (r"\spoolss", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", 18),
            (r"\chrome.sync.12345", r"C:\Program Files\Google\Chrome\Application\chrome.exe", 17),
            (r"\status_update", r"C:\Program Files\Vendor\updater.exe", 17),
        ):
            self.assertFalse(hits("WLH-028", sm(event_id, PipeName=pipe, Image=image)))
        self.assertTrue(hits("WLH-028", sm(17, PipeName=r"\spoolss", Image=USER + "spoolsv.exe")))

    def test_pipe_echo_and_normal_service(self):
        command = r'cmd.exe /c echo token > \\.\pipe\example'
        self.assertTrue(hits("WLH-028", sysmon(0, SYSTEM + "cmd.exe", command)))
        self.assertEqual(hits("WLH-028", ev(7045, channel="System", ImagePath=command, ServiceName="PipeService"))[0].severity, "high")
        self.assertFalse(hits("WLH-028", sysmon(0, SYSTEM + "cmd.exe", "cmd /c echo ready > C:\\Temp\\ready.txt")))
        self.assertFalse(hits("WLH-028", ev(7045, channel="System", ImagePath=r'"C:\Program Files\Vendor\service.exe"', ServiceName="VendorService")))

    def test_repeated_pipe_connections_are_grouped(self):
        events = [sm(18, PipeName=r"\postex_123", Image=USER + "agent.exe") for _ in range(8)]
        found = run_rules(events, only={"WLH-028"})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].event_count, 8)


class RegistryPersistenceExtensions(unittest.TestCase):
    def test_new_keys_and_normal_service_dll(self):
        for key in (
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\app.exe",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{123}\DatabasePath",
            r"HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\0001\PackedCatalogItem",
            r"HKLM\System\CurrentControlSet\Control\NetworkProvider\Order\ProviderOrder",
            r"HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes",
            r"HKLM\System\CurrentControlSet\Control\Print\Monitors\CustomMonitor\Driver",
            r"HKLM\System\CurrentControlSet\Services\CustomSvc\Parameters\ServiceDll",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0\Script",
            r"HKCU\Software\Microsoft\IEAK\GroupPolicy\PendingGPOs\Path1",
        ):
            self.assertTrue(hits("WLH-019", sm(13, Image=SYSTEM + "reg.exe", TargetObject=key, Details=USER + "module.dll")), key)
        key = r"HKLM\System\CurrentControlSet\Services\ExampleSvc\Parameters\ServiceDll"
        for module in (r"%SystemRoot%\System32\example.dll", r"C:\Program Files\Vendor\module.dll"):
            self.assertFalse(hits("WLH-019", sm(13, Image=SYSTEM + "reg.exe", TargetObject=key, Details=module)))
        self.assertFalse(hits("WLH-019", sm(13, Image=SYSTEM + "msiexec.exe", TargetObject=key, Details=USER + "module.dll")))

    def test_boot_defaults_network_defaults_and_smss(self):
        boot = r"HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute"
        self.assertFalse(hits("WLH-019", sm(13, Image=SYSTEM + "reg.exe", TargetObject=boot, Details="autocheck autochk *")))
        self.assertTrue(hits("WLH-019", sm(13, Image=SYSTEM + "reg.exe", TargetObject=boot, Details="autocheck autochk *\r\nC:\\Temp\\startup.exe")))
        self.assertFalse(hits("WLH-019", sm(13, Image=SYSTEM + "reg.exe", TargetObject=r"HKLM\System\CurrentControlSet\Control\NetworkProvider\Order\ProviderOrder", Details="RDPNP,LanmanWorkstation,webclient")))
        self.assertTrue(hits("WLH-019", sysmon(0, USER + "startup.exe", "startup", SYSTEM + "smss.exe")))
        self.assertFalse(hits("WLH-019", sysmon(0, SYSTEM + "autochk.exe", "autochk *", SYSTEM + "smss.exe")))
        shell = sysmon(0, SYSTEM + "cmd.exe", "cmd", SYSTEM + "smss.exe")
        self.assertFalse(hits("WLH-019", shell))
        self.assertTrue(hits("WLH-024", shell))


class RegistryDefenseRules(unittest.TestCase):
    def test_dangerous_values_and_protective_settings(self):
        cases = [
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA", "0", "1"),
            (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging", "0", "1"),
            (r"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy", "Bypass", "RemoteSigned"),
            (r"HKCU\Environment\__PSLockdownPolicy", "0", "4"),
            (r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware", "1", "0"),
            (r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring", "1", "0"),
            (r"HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential", "1", "0"),
            (r"HKLM\System\CurrentControlSet\Control\Lsa\RunAsPPL", "0", "2"),
            (r"HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections", "0", "1"),
            (r"HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber", "3390", "3389"),
            (r"HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall", "0", "1"),
            (r"HKCU\Software\Microsoft\Office\16.0\Excel\Security\AccessVBOM", "1", "0"),
        ]
        for key, bad, good in cases:
            with self.subTest(key=key):
                self.assertTrue(hits("WLH-029", sm(13, Image=SYSTEM + "reg.exe", TargetObject=key, Details=bad)))
                self.assertFalse(hits("WLH-029", sm(13, Image=SYSTEM + "reg.exe", TargetObject=key, Details=good)))
        key = cases[0][0]
        self.assertTrue(hits("WLH-029", sm(13, Image=SYSTEM + "reg.exe", TargetObject=key, Details="DWORD (0x00000000)")))
        self.assertFalse(hits("WLH-029", sm(13, Image=SYSTEM + "reg.exe", TargetObject=key, Details="")))
        self.assertFalse(hits("WLH-029", sm(12, Image=SYSTEM + "reg.exe", TargetObject=key, EventType="CreateKey")))

    def test_legitimate_defender_update_and_exclusions(self):
        key = r"HKLM\SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware"
        self.assertFalse(hits("WLH-029", sm(13, Image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2401\MsMpEng.exe", TargetObject=key, Details="DWORD (0x00000001)")))
        self.assertTrue(hits("WLH-029", sm(13, Image=USER + "MsMpEng.exe", TargetObject=key, Details="1")))
        key = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\BuildCache"
        self.assertEqual(hits("WLH-029", sm(13, Image=SYSTEM + "reg.exe", TargetObject=key, Details="DWORD (0x00000000)"))[0].severity, "low")
        self.assertFalse(hits("WLH-029", sm(12, Image=SYSTEM + "reg.exe", TargetObject=key, EventType="DeleteValue")))

    def test_deletions_and_user_clearing_explorer_history(self):
        key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        self.assertTrue(hits("WLH-029", sm(12, Image=SYSTEM + "reg.exe", TargetObject=key, EventType="DeleteKey")))
        self.assertFalse(hits("WLH-029", sm(12, Image=r"C:\Windows\explorer.exe", TargetObject=key, EventType="DeleteKey")))
        key = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        self.assertTrue(hits("WLH-029", sm(12, Image=SYSTEM + "reg.exe", TargetObject=key, EventType="DeleteKey")))
        self.assertFalse(hits("WLH-029", sm(12, Image=SYSTEM + "svchost.exe", TargetObject=key, EventType="DeleteKey")))
        key = r"HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp\0.0.0.0/4444"
        self.assertTrue(hits("WLH-029", sm(13, Image=SYSTEM + "netsh.exe", TargetObject=key, Details="localhost/3389")))


class SuspiciousFileRules(unittest.TestCase):
    def test_startup_and_legitimate_installer(self):
        target = USER + r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk"
        self.assertTrue(hits("WLH-030", sm(11, Image=SYSTEM + "powershell.exe", TargetFilename=target)))
        self.assertFalse(hits("WLH-030", sm(11, Image=SYSTEM + "msiexec.exe", TargetFilename=target)))
        self.assertFalse(hits("WLH-030", sm(11, Image=r"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe", TargetFilename=target)))
        self.assertFalse(hits("WLH-030", sm(11, Image=USER + r"AppData\Local\Microsoft\OneDrive\OneDrive.exe", TargetFilename=target)))
        self.assertFalse(hits("WLH-030", sm(11, Image=r"C:\Windows\explorer.exe", TargetFilename=target.replace("update.lnk", "desktop.ini"))))

    def test_credential_dumps_and_normal_browser_crashes(self):
        for image, target in ((SYSTEM + "lsass.exe", r"C:\Temp\credentials.dmp"),
                              (SYSTEM + "rdrleakdiag.exe", r"C:\Temp\process.dmp"),
                              (USER + "dump.exe", r"C:\Temp\lsass_424.dmp"),
                              (SYSTEM + "lsass.exe", r"C:\Windows\System32\mimilsa.log")):
            self.assertEqual(hits("WLH-030", sm(11, Image=image, TargetFilename=target))[0].severity, "high")
        for image, target in ((SYSTEM + "WerFault.exe", r"C:\Temp\lsass.dmp"),
                              (r"C:\Program Files\Google\Chrome\Application\chrome.exe", USER + r"AppData\Local\Google\Chrome\User Data\Crashpad\reports\crash.dmp"),
                              (SYSTEM + "Taskmgr.exe", USER + r"AppData\Local\Temp\notepad.dmp")):
            self.assertFalse(hits("WLH-030", sm(11, Image=image, TargetFilename=target)))

    def test_unquoted_candidates_and_print_driver_updates(self):
        for target in (r"C:\Program.exe", r"D:\Program Files\Vendor.exe", SYSTEM + r"spool\drivers\x64\3\plugin.dll"):
            self.assertTrue(hits("WLH-030", sm(11, Image=SYSTEM + "powershell.exe", TargetFilename=target)))
        self.assertFalse(hits("WLH-030", sm(11, Image=SYSTEM + "spoolsv.exe", TargetFilename=SYSTEM + r"spool\drivers\x64\3\printer.dll")))
        self.assertFalse(hits("WLH-030", sm(11, Image=SYSTEM + "drvinst.exe", TargetFilename=SYSTEM + r"spool\drivers\x64\3\printer.dll")))
        self.assertFalse(hits("WLH-030", sm(11, Image=SYSTEM + "msiexec.exe", TargetFilename=r"C:\Program Files\Vendor\service.exe")))

    def test_timestomp_and_legitimate_extraction(self):
        values = dict(TargetFilename=USER + r"Downloads\payload.exe", CreationUtcTime="2018-01-01 10:00:00.0000000", PreviousCreationUtcTime="2026-11-13 10:00:00.0000000")
        self.assertTrue(hits("WLH-030", sm(2, Image=SYSTEM + "powershell.exe", **values)))
        for image in (r"C:\Windows\explorer.exe", r"C:\Program Files\7-Zip\7z.exe", SYSTEM + "msiexec.exe", r"C:\Program Files\Microsoft Visual Studio\MSBuild\Current\Bin\MSBuild.exe"):
            self.assertFalse(hits("WLH-030", sm(2, Image=image, **values)))
        values["CreationUtcTime"] = "2026-11-13 09:59:30"
        self.assertFalse(hits("WLH-030", sm(2, Image=SYSTEM + "powershell.exe", **values)))
        values["CreationUtcTime"] = "sin fecha"
        self.assertFalse(hits("WLH-030", sm(2, Image=SYSTEM + "powershell.exe", **values)))


class ShellNetworkRules(unittest.TestCase):
    def test_public_connection_and_local_office_activity(self):
        self.assertEqual(hits("WLH-031", sm(3, Image=SYSTEM + "mshta.exe", DestinationIp="8.8.8.8", DestinationPort="443", Initiated="true"))[0].severity, "medium")
        for image, address in ((SYSTEM + "powershell.exe", "10.10.0.10"),
                               (SYSTEM + "wscript.exe", "127.0.0.1"),
                               (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "8.8.8.8")):
            self.assertFalse(hits("WLH-031", sm(3, Image=image, DestinationIp=address, DestinationPort="443", Initiated="true")))
        self.assertEqual(hits("WLH-031", sm(3, Image=SYSTEM + "powershell.exe", DestinationIp="8.8.8.8", DestinationPort="443"))[0].severity, "low")
        self.assertFalse(hits("WLH-031", sm(3, Image=SYSTEM + "mshta.exe", DestinationIp="8.8.8.8", DestinationPort="443", Initiated="false")))
        self.assertFalse(hits("WLH-031", sm(3, Image=SYSTEM + "mshta.exe", DestinationIp="no es una IP", DestinationPort="443")))

    def test_rdp_unexpected_process_and_legitimate_clients(self):
        for address in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "10.10.0.10"):
            self.assertEqual(hits("WLH-031", sm(3, Image=USER + "proxy.exe", DestinationIp=address, DestinationPort="3389"))[0].severity, "high")
        for image in (SYSTEM + "mstsc.exe", SYSTEM + "svchost.exe", r"C:\Program Files\Remote Desktop\msrdc.exe"):
            self.assertFalse(hits("WLH-031", sm(3, Image=image, DestinationIp="127.0.0.1", DestinationPort="3389")))
        self.assertEqual(hits("WLH-031", sm(3, Image=SYSTEM + r"OpenSSH\ssh.exe", DestinationIp="127.0.0.1", DestinationPort="3389"))[0].severity, "low")

    def test_security_wfp_direction_and_system(self):
        fields = dict(Application=r"\device\harddiskvolume2\tools\proxy.exe", DestAddress="127.0.0.1", DestPort="3389", Direction="%%14593")
        self.assertTrue(hits("WLH-031", ev(5156, **fields)))
        fields["Direction"] = "%%14592"
        self.assertFalse(hits("WLH-031", ev(5156, **fields)))
        fields.update(Direction="%%14593", Application="System")
        self.assertFalse(hits("WLH-031", ev(5156, **fields)))
        fields["Application"] = r"\device\harddiskvolume2\windows\system32\mstsc.exe"
        self.assertFalse(hits("WLH-031", ev(5156, **fields)))


if __name__ == "__main__":
    unittest.main()
