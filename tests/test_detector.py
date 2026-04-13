"""
tests/test_detector.py — Unit Tests for Threat Detection System
================================================================
Tests cover the core parsing and detection logic to ensure
reliability across edge cases a SOC analyst might encounter.

Run with:
    python -m pytest tests/ -v
    # or from project root:
    python -m pytest -v
"""

import sys
import os
import unittest

# Allow imports from project root and package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_detection.parser   import LogParser, LogEntry
from threat_detection.detector import ThreatDetector, IPProfile


# ─────────────────────────────────────────────
#  Parser Tests
# ─────────────────────────────────────────────

class TestLogParser(unittest.TestCase):
    """Tests for the regex-based log parser."""

    def _parse_line(self, line: str):
        """Helper: parse a single line via a temp file."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(line + "\n")
            tmp = f.name
        parser = LogParser(tmp)
        entries = parser.parse()
        os.unlink(tmp)
        return entries

    def test_failed_password_parsed(self):
        line = "Apr 13 08:01:12 server sshd[1001]: Failed password for root from 1.2.3.4 port 22 ssh2"
        entries = self._parse_line(line)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e.status, "failed")
        self.assertEqual(e.ip_address, "1.2.3.4")
        self.assertEqual(e.username, "root")
        self.assertEqual(e.port, 22)

    def test_successful_login_parsed(self):
        line = "Apr 13 08:02:00 server sshd[1002]: Accepted password for deploy from 10.0.0.1 port 54321 ssh2"
        entries = self._parse_line(line)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e.status, "success")
        self.assertEqual(e.ip_address, "10.0.0.1")
        self.assertEqual(e.username, "deploy")

    def test_publickey_login_parsed(self):
        line = "Apr 13 09:00:00 server sshd[1003]: Accepted publickey for admin from 172.16.0.1 port 50000 ssh2"
        entries = self._parse_line(line)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].status, "success")

    def test_invalid_user_parsed(self):
        line = "Apr 13 09:05:00 server sshd[1004]: Invalid user hacker from 5.6.7.8"
        entries = self._parse_line(line)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e.status, "invalid_user")
        self.assertEqual(e.ip_address, "5.6.7.8")
        self.assertEqual(e.username, "hacker")

    def test_failed_invalid_user_combined(self):
        line = "Apr 13 09:10:00 server sshd[1005]: Failed password for invalid user ghost from 9.9.9.9 port 22 ssh2"
        entries = self._parse_line(line)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].status, "failed")
        self.assertEqual(entries[0].ip_address, "9.9.9.9")

    def test_irrelevant_line_ignored(self):
        line = "Apr 13 08:00:00 server systemd[1]: Started Session 5 of user ubuntu."
        entries = self._parse_line(line)
        self.assertEqual(len(entries), 0)

    def test_empty_file_returns_empty(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            tmp = f.name
        parser = LogParser(tmp)
        entries = parser.parse()
        os.unlink(tmp)
        self.assertEqual(entries, [])

    def test_missing_file_raises(self):
        parser = LogParser("/nonexistent/path/auth.log")
        with self.assertRaises(FileNotFoundError):
            parser.parse()

    def test_parser_stats(self):
        lines = [
            "Apr 13 08:01:00 server sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2",
            "Apr 13 08:01:01 server sshd[2]: Failed password for root from 1.1.1.1 port 22 ssh2",
            "Apr 13 08:01:02 server sshd[3]: Accepted password for admin from 2.2.2.2 port 22 ssh2",
        ]
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("\n".join(lines) + "\n")
            tmp = f.name
        parser = LogParser(tmp)
        parser.parse()
        os.unlink(tmp)
        stats = parser.get_stats()
        self.assertEqual(stats["failed"],  2)
        self.assertEqual(stats["success"], 1)


# ─────────────────────────────────────────────
#  Detector Tests
# ─────────────────────────────────────────────

def _make_entry(ip, status, username="root", timestamp="Apr 13 08:00:00"):
    """Factory for LogEntry objects used in detector tests."""
    return LogEntry(
        raw_line="",
        timestamp=timestamp,
        hostname="server",
        process="sshd",
        pid=1000,
        ip_address=ip,
        username=username,
        port=22,
        status=status,
    )


class TestThreatDetector(unittest.TestCase):
    """Tests for the detection engine rules."""

    def test_brute_force_alert_raised(self):
        """6 failures from same IP should trigger BRUTE_FORCE with threshold=5."""
        entries = [_make_entry("1.2.3.4", "failed") for _ in range(6)]
        detector = ThreatDetector(threshold=5)
        alerts = detector.analyse(entries)
        types = [a.alert_type for a in alerts]
        self.assertIn("BRUTE_FORCE", types)

    def test_brute_force_not_raised_below_threshold(self):
        """4 failures should NOT trigger BRUTE_FORCE with threshold=5."""
        entries = [_make_entry("1.2.3.4", "failed") for _ in range(4)]
        detector = ThreatDetector(threshold=5)
        alerts = detector.analyse(entries)
        types = [a.alert_type for a in alerts]
        self.assertNotIn("BRUTE_FORCE", types)

    def test_credential_spray_detected(self):
        """Multiple usernames from one IP should trigger CREDENTIAL_SPRAY."""
        users = ["root", "admin", "oracle", "postgres", "mysql"]
        entries = [_make_entry("5.5.5.5", "failed", username=u) for u in users]
        detector = ThreatDetector(threshold=5, spray_threshold=4)
        alerts = detector.analyse(entries)
        types = [a.alert_type for a in alerts]
        self.assertIn("CREDENTIAL_SPRAY", types)

    def test_suspicious_login_detected(self):
        """Failure then success from same IP → SUSPICIOUS_LOGIN."""
        entries = [
            _make_entry("7.7.7.7", "failed"),
            _make_entry("7.7.7.7", "failed"),
            _make_entry("7.7.7.7", "success"),
        ]
        detector = ThreatDetector(threshold=5)
        alerts = detector.analyse(entries)
        types = [a.alert_type for a in alerts]
        self.assertIn("SUSPICIOUS_LOGIN", types)

    def test_probe_detected(self):
        """2-4 failures below threshold → PROBE alert."""
        entries = [_make_entry("8.8.8.8", "failed") for _ in range(3)]
        detector = ThreatDetector(threshold=5)
        alerts = detector.analyse(entries)
        types = [a.alert_type for a in alerts]
        self.assertIn("PROBE", types)

    def test_clean_ip_no_alert(self):
        """Single successful login should raise no alerts."""
        entries = [_make_entry("10.0.0.1", "success")]
        detector = ThreatDetector(threshold=5)
        alerts = detector.analyse(entries)
        self.assertEqual(alerts, [])

    def test_alert_severity_critical_for_high_volume(self):
        """15 failures (3× threshold of 5) should be CRITICAL."""
        entries = [_make_entry("2.2.2.2", "failed") for _ in range(15)]
        detector = ThreatDetector(threshold=5)
        alerts = detector.analyse(entries)
        bf_alerts = [a for a in alerts if a.alert_type == "BRUTE_FORCE"]
        self.assertTrue(any(a.severity == "CRITICAL" for a in bf_alerts))

    def test_custom_threshold_respected(self):
        """With threshold=10, 8 failures should not trigger BRUTE_FORCE."""
        entries = [_make_entry("3.3.3.3", "failed") for _ in range(8)]
        detector = ThreatDetector(threshold=10)
        alerts = detector.analyse(entries)
        types = [a.alert_type for a in alerts]
        self.assertNotIn("BRUTE_FORCE", types)

    def test_summary_counts(self):
        """Summary dict should accurately reflect analysed data."""
        entries = (
            [_make_entry("1.1.1.1", "failed") for _ in range(6)] +
            [_make_entry("2.2.2.2", "success")]
        )
        detector = ThreatDetector(threshold=5)
        detector.analyse(entries)
        summary = detector.get_summary()
        self.assertEqual(summary["total_failed_attempts"],  6)
        self.assertEqual(summary["total_success_attempts"], 1)
        self.assertEqual(summary["total_ips_seen"], 2)

    def test_multiple_ips_independent(self):
        """Alerts from different IPs should not interfere with each other."""
        entries = (
            [_make_entry("9.9.9.1", "failed") for _ in range(6)] +
            [_make_entry("9.9.9.2", "failed") for _ in range(6)]
        )
        detector = ThreatDetector(threshold=5)
        alerts = detector.analyse(entries)
        flagged_ips = {a.ip_address for a in alerts if a.alert_type == "BRUTE_FORCE"}
        self.assertIn("9.9.9.1", flagged_ips)
        self.assertIn("9.9.9.2", flagged_ips)


# ─────────────────────────────────────────────
#  Integration Test
# ─────────────────────────────────────────────

class TestIntegration(unittest.TestCase):
    """End-to-end test using the bundled sample.log."""

    def test_sample_log_produces_alerts(self):
        sample_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "sample.log"
        )
        if not os.path.exists(sample_path):
            self.skipTest("data/sample.log not found")

        parser  = LogParser(sample_path)
        entries = parser.parse()
        self.assertGreater(len(entries), 0, "sample.log should yield parsed entries")

        detector = ThreatDetector(threshold=5)
        alerts   = detector.analyse(entries)
        self.assertGreater(len(alerts), 0, "sample.log should trigger alerts")

        types = {a.alert_type for a in alerts}
        self.assertIn("BRUTE_FORCE", types)
        self.assertIn("CREDENTIAL_SPRAY", types)


if __name__ == "__main__":
    unittest.main(verbosity=2)
