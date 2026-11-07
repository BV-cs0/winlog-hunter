import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from helpers import SAMPLE  # noqa: F401  (añade src/ al path)

from winlog_hunter.parsers import ParseError, load_events, parse_timestamp

EXPECTED = datetime(2026, 11, 3, 9, 10, tzinfo=timezone.utc)

WEVTUTIL_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID>
<TimeCreated SystemTime='2026-11-03T09:10:00.1234567Z'/><Channel>Security</Channel>
<Computer>SRV-APP</Computer></System><EventData>
<Data Name='TargetUserName'>administrador</Data><Data Name='IpAddress'>203.0.113.50</Data>
<Data Name='LogonType'>10</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID>
<TimeCreated SystemTime='2026-11-03T09:20:00Z'/><Channel>Security</Channel>
<Computer>DC01</Computer></System><UserData>
<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>
<SubjectUserName>mlopez</SubjectUserName></LogFileCleared></UserData></Event>
"""


class TimestampTests(unittest.TestCase):
    def test_variants(self):
        for value in (
            "2026-11-03T09:10:00Z",
            "2026-11-03T09:10:00.0000000Z",
            "2026-11-03T10:10:00+01:00",
            "2026-11-03 09:10:00",
            "2026-11-03T09:10:00.5Z",
        ):
            with self.subTest(value=value):
                self.assertEqual(parse_timestamp(value).replace(microsecond=0), EXPECTED)

    def test_powershell_date_and_epoch(self):
        ms = int(EXPECTED.timestamp() * 1000)
        self.assertEqual(parse_timestamp(f"/Date({ms})/"), EXPECTED)
        self.assertEqual(parse_timestamp(ms), EXPECTED)

    def test_invalid(self):
        with self.assertRaises(ParseError):
            parse_timestamp("ayer por la tarde")


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_wevtutil_xml_utf16(self):
        path = self.dir / "security.xml"
        path.write_text(WEVTUTIL_XML, encoding="utf-16")  # como hace '>' en PowerShell 5.1
        result = load_events([path])
        self.assertEqual(result.warnings, [])
        failed, cleared = result.events
        self.assertEqual(failed.event_id, 4625)
        self.assertEqual(failed.computer, "SRV-APP")
        self.assertEqual(failed.get("IpAddress"), "203.0.113.50")
        self.assertEqual(failed.timestamp.microsecond, 123456)
        self.assertEqual(cleared.get("SubjectUserName"), "mlopez")
        self.assertEqual(cleared.provider, "Microsoft-Windows-Eventlog")

    def test_doctype_is_rejected(self):
        path = self.dir / "evil.xml"
        path.write_text('<!DOCTYPE x [<!ENTITY a "aaaa">]><Event/>', encoding="utf-8")
        result = load_events([path])
        self.assertEqual(result.events, [])
        self.assertIn("DOCTYPE", result.warnings[0])

    def test_jsonl_skips_bad_lines(self):
        path = self.dir / "logs.jsonl"
        good = {"EventID": 4720, "TimeCreated": "2026-11-03T09:10:00Z", "Computer": "DC01",
                "EventData": {"TargetUserName": "nuevo"}}
        path.write_text(json.dumps(good) + "\n{roto\n" + json.dumps({"EventID": 1}) + "\n", encoding="utf-8")
        result = load_events([path])
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].get("TargetUserName"), "nuevo")
        self.assertEqual(len(result.warnings), 2)

    def test_json_array_and_flat_fields(self):
        path = self.dir / "export.json"
        path.write_text(json.dumps([{"Id": "4624", "TimeCreated": "2026-11-03T09:10:00Z",
                                     "MachineName": "WS01", "LogName": "Security", "LogonType": 3}]),
                        encoding="utf-8-sig")
        event = load_events([path]).events[0]
        self.assertEqual((event.event_id, event.computer, event.channel), (4624, "WS01", "Security"))
        self.assertEqual(event.get("LogonType"), "3")

    def test_winlogbeat_format(self):
        record = {
            "@timestamp": "2026-11-03T09:10:00.000Z",
            "host": {"name": "srv-app.corp.local"},
            "event": {"code": "4625", "provider": "Microsoft-Windows-Security-Auditing"},
            "winlog": {
                "event_id": 4625,
                "channel": "Security",
                "computer_name": "SRV-APP.corp.local",
                "event_data": {"TargetUserName": "administrador", "IpAddress": "203.0.113.50"},
            },
        }
        path = self.dir / "winlogbeat.ndjson"
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        result = load_events([path])
        self.assertEqual(result.warnings, [])
        event = result.events[0]
        self.assertEqual((event.event_id, event.channel, event.computer), (4625, "Security", "SRV-APP.corp.local"))
        self.assertEqual(event.get("IpAddress"), "203.0.113.50")
        self.assertEqual(event.timestamp, EXPECTED)

    def test_directory_and_missing_path(self):
        (self.dir / "a.jsonl").write_text(
            json.dumps({"EventID": 1102, "TimeCreated": "2026-11-03T09:00:00Z"}) + "\n", encoding="utf-8")
        (self.dir / "notas.txt").write_text("ignorar", encoding="utf-8")
        result = load_events([self.dir])
        self.assertEqual((result.files, len(result.events)), (1, 1))
        with self.assertRaises(FileNotFoundError):
            load_events([self.dir / "no-existe.evtx"])

    def test_sample_loads_cleanly(self):
        result = load_events([SAMPLE])
        self.assertGreater(len(result.events), 100)
        self.assertEqual(result.warnings, [])


if __name__ == "__main__":
    unittest.main()
