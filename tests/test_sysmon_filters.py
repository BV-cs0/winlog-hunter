"""Comprueba la intención de los filtros XML; no sustituye la validación nativa de Sysmon."""
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from pathlib import Path

from helpers import ROOT
from winlog_hunter import local


def matches(node, data, relation='or'):
    """Evalúa el subconjunto de condiciones usado en esta configuración y sus ejemplos."""
    if node.tag == 'Rule':
        return matches_children(node, data, node.get('groupRelation', relation))
    actual = str(data.get(node.tag, '')).lower()
    expected = (node.text or '').lower()
    parts = expected.split(';')
    condition = node.get('condition', 'is')
    operations = {
        'is': lambda: actual == expected,
        'is not': lambda: actual != expected,
        'is any': lambda: actual in parts,
        'contains': lambda: expected in actual,
        'contains any': lambda: any(p in actual for p in parts),
        'contains all': lambda: all(p in actual for p in parts),
        'excludes any': lambda: not any(p in actual for p in parts),
        'begin with': lambda: actual.startswith(expected),
        'end with': lambda: actual.endswith(expected),
        'not end with': lambda: not actual.endswith(expected),
    }
    if condition not in operations:
        raise AssertionError('Condición sin verificación: ' + condition)
    return operations[condition]()


def matches_children(node, data, relation):
    values = [matches(child, data, relation) for child in node]
    return all(values) if relation == 'and' else any(values)


class SysmonFilters(unittest.TestCase):
    def setUp(self):
        self.root = ET.parse(local.SYSMON_CONFIG).getroot()

    def captured(self, tag, **data):
        includes, excludes = [], []
        for group in self.root.findall('EventFiltering/RuleGroup'):
            for entry in group.findall(tag):
                if not len(entry):
                    value = entry.get('onmatch') == 'exclude'
                    if value:
                        includes.append(True)
                    continue
                value = matches_children(entry, data, group.get('groupRelation', 'or'))
                (includes if entry.get('onmatch') == 'include' else excludes).append(value)
        # Los tipos configurados solo con exclusiones registran por defecto.
        all_entries = list(self.root.iter(tag))
        if all_entries and not any(e.get('onmatch') == 'include' for e in all_entries):
            includes.append(True)
        return any(includes) and not any(excludes)

    def test_all_event_types_used_are_active(self):
        used = {'ProcessCreate','FileCreateTime','NetworkConnect','ImageLoad','CreateRemoteThread','ProcessAccess','FileCreate','RegistryEvent','PipeEvent','WmiEvent','ProcessTampering'}
        for tag in used:
            entries = list(self.root.iter(tag))
            self.assertTrue(entries, tag)
            self.assertFalse(any(e.get('onmatch') == 'include' and not len(e) for e in entries), tag)
        self.assertFalse(self.captured('DnsQuery', QueryName='example.org'))

    def test_unsigned_and_autoelevated_dll_without_global_exclusion(self):
        self.assertTrue(self.captured('ImageLoad', Image=r'C:\Windows\System32\rundll32.exe', ImageLoaded=r'C:\Users\operador\plugin.dll', Signed='false'))
        self.assertFalse(self.captured('ImageLoad', Image=r'C:\Windows\System32\rundll32.exe', ImageLoaded=r'C:\Windows\System32\shell32.dll', Signed='true'))
        self.assertFalse(self.captured('ImageLoad', Image=r'C:\Program Files\Vendor\app.exe', ImageLoaded=r'C:\Users\operador\plugin.dll', Signed='false'))
        self.assertTrue(self.captured('ImageLoad', Image=r'C:\Windows\System32\cliconfg.exe', ImageLoaded=r'C:\Windows\System32\version.dll', Signed='false'))
        self.assertTrue(self.captured('ImageLoad', Image=r'C:\Users\operador\winword.exe', ImageLoaded=r'C:\Users\operador\wwlib.dll', Signed='false'))

    def test_access_requires_permissions_and_user_path_or_unknown(self):
        self.assertTrue(self.captured('ProcessAccess', SourceImage=r'C:\Users\operador\loader.exe', TargetImage=r'C:\Windows\System32\notepad.exe', GrantedAccess='0x143a'))
        self.assertFalse(self.captured('ProcessAccess', SourceImage=r'C:\Users\operador\inventory.exe', TargetImage=r'C:\Windows\System32\notepad.exe', GrantedAccess='0x1000'))
        self.assertFalse(self.captured('ProcessAccess', SourceImage=r'C:\Program Files\Vendor\inventory.exe', TargetImage=r'C:\Windows\System32\notepad.exe', GrantedAccess='0x143a'))
        self.assertTrue(self.captured('ProcessAccess', SourceImage=r'C:\Windows\System32\rundll32.exe', TargetImage=r'C:\Windows\System32\notepad.exe', GrantedAccess='0x1000', CallTrace='UNKNOWN(1234)'))
        self.assertFalse(self.captured('ProcessAccess', SourceImage=r'C:\Windows\System32\wininit.exe', TargetImage=r'C:\Windows\System32\lsass.exe', GrantedAccess='0x1fffff'))
        self.assertTrue(self.captured('ProcessAccess', SourceImage=r'C:\Windows\System32\wininit.exe', TargetImage=r'C:\Windows\System32\notepad.exe', GrantedAccess='0x143a', CallTrace='UNKNOWN(1234)'))

    def test_files_pipes_and_timestamps_are_filtered(self):
        for target in (r'C:\Program.exe', r'C:\Temp\process.dmp', r'C:\Windows\System32\mimilsa.log', r'C:\Windows \System32\version.dll', r'C:\Windows\System32\sysprep\version.dll', r'C:\Windows\System32\spool\drivers\x64\3\printer.dll', r'C:\Users\operador\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk'):
            self.assertTrue(self.captured('FileCreate', TargetFilename=target), target)
        self.assertFalse(self.captured('FileCreate', TargetFilename=r'C:\Users\operador\Documents\normal.txt'))
        self.assertTrue(self.captured('FileCreateTime', Image=r'C:\Tools\mace.exe', TargetFilename=r'C:\Users\operador\app.exe'))
        self.assertFalse(self.captured('FileCreateTime', Image=r'C:\Tools\mace.exe', TargetFilename=r'C:\Users\operador\normal.txt'))
        self.assertFalse(self.captured('FileCreateTime', Image=r'C:\Windows\explorer.exe', TargetFilename=r'C:\Users\operador\app.exe'))
        self.assertTrue(self.captured('PipeEvent', PipeName=r'\postex_123'))
        self.assertFalse(self.captured('PipeEvent', PipeName=r'\chrome.sync.123'))
        self.assertTrue(self.captured('PipeEvent', PipeName=r'\spoolss', EventType='CreatePipe', Image=r'C:\Tools\loader.exe'))
        self.assertFalse(self.captured('PipeEvent', PipeName=r'\spoolss', EventType='ConnectPipe', Image=r'C:\Program Files\Microsoft Office\WINWORD.EXE'))
        self.assertFalse(self.captured('PipeEvent', PipeName=r'\spoolss', EventType='CreatePipe', Image=r'C:\Windows\System32\spoolsv.exe'))

    def test_registry_coverage_and_mru_only_on_deletion(self):
        for key in (r'HKCU\Software\Classes\ms-settings\shell\open\command', r'HKU\SID_Classes\mscfile\shell\open\command', r'HKCU\Environment\windir', r'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging', r'HKLM\System\CurrentControlSet\Services\Svc\Parameters\ServiceDll', r'HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths\C:\Build'):
            self.assertTrue(self.captured('RegistryEvent', TargetObject=key, EventType='SetValue'), key)
        key = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\1'
        self.assertFalse(self.captured('RegistryEvent', TargetObject=key, EventType='SetValue'))
        self.assertTrue(self.captured('RegistryEvent', TargetObject=key, EventType='DeleteValue'))
        self.assertFalse(self.captured('RegistryEvent', TargetObject=r'HKCU\Software\Vendor\WindowPosition', EventType='SetValue'))

    def test_rdp_loopback_not_masked_by_network_exclusion(self):
        self.assertTrue(self.captured('NetworkConnect', Image=r'C:\Tools\proxy.exe', DestinationIp='127.0.0.1', DestinationPort='3389'))
        self.assertFalse(self.captured('NetworkConnect', Image=r'C:\Windows\System32\mstsc.exe', DestinationIp='127.0.0.1', DestinationPort='3389'))
        self.assertTrue(self.captured('NetworkConnect', Image=r'C:\Windows\System32\notepad.exe', DestinationIp='8.8.8.8', DestinationPort='443'))
        self.assertFalse(self.captured('NetworkConnect', Image=r'C:\Program Files\Google\Chrome\Application\chrome.exe', DestinationIp='8.8.8.8', DestinationPort='443'))


class ExportAndAuditIntegration(unittest.TestCase):
    def test_new_channels_and_missing_channel_warning(self):
        required = {'Application','Windows PowerShell','Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-Bits-Client/Operational'}
        self.assertTrue(required.issubset(local.LOGS))
        def execute(command):
            if command[:2] == ['wevtutil','el']:
                return CompletedProcess(command, 0, 'Security\nSystem\nApplication\n', '')
            return CompletedProcess(command, 0, '', '')
        with TemporaryDirectory() as tmp, patch.object(local, '_run', side_effect=execute):
            result = local.export_logs(24, Path(tmp))
        self.assertEqual(len(result.files), 3)
        self.assertTrue(any('Windows PowerShell' in m and 'no existe' in m for m in result.messages))
        self.assertTrue(any('Defender' in m and 'no existe' in m for m in result.messages))

    def test_audit_plan_does_not_enable_domain_or_high_volume_categories(self):
        commands = ' '.join(' '.join(x) for x in local.audit_plan()).lower()
        self.assertIn('0cce922f', commands)
        for guid in ('0cce923c','0cce9240','0cce9242','0cce9231','0cce9226'):
            self.assertNotIn(guid, commands)


if __name__ == '__main__':
    unittest.main()
