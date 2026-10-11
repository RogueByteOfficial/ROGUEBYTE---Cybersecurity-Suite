"""
ROGUEBYTE Test Suite
Comprehensive unit and integration tests covering security rules, DoS detection,
load test safety boundaries, database persistence, and network diagnostics.
"""

import unittest
import os
import sys
import tempfile
import json

# --- Bootstrap sys.path & module resolution ---
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_CURRENT_DIR = os.path.dirname(_TEST_DIR)
_PARENT_DIR = os.path.dirname(_CURRENT_DIR)

if _CURRENT_DIR not in sys.path:
    sys.path.insert(0, _CURRENT_DIR)
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

if "roguebyte" not in sys.modules:
    try:
        import roguebyte
    except ModuleNotFoundError:
        import types
        _pkg = types.ModuleType("roguebyte")
        _pkg.__path__ = [_CURRENT_DIR]
        _pkg.__file__ = os.path.join(_CURRENT_DIR, "__init__.py")
        sys.modules["roguebyte"] = _pkg

from roguebyte.config.settings import Config, SecurityPolicy, DEFAULT_ALLOWLIST
from roguebyte.core.security import SecurityValidator, SecurityViolationException
from roguebyte.database.db import DatabaseManager
from roguebyte.modules.systemmonitor import SystemMonitor
from roguebyte.modules.networkdiagnostics import NetworkDiagnostics
from roguebyte.modules.loadtesting import LoadTestEngine
from roguebyte.modules.dosdetection import DoSDetectionEngine
from roguebyte.modules.wslintegration import WSLIntegration
from roguebyte.modules.reporting import ReportGenerator

class TestSecurityPolicy(unittest.TestCase):
    def test_allowlist_permits_loopback(self):
        self.assertEqual(SecurityValidator.validate_target_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(SecurityValidator.validate_target_host("localhost"), "localhost")
        self.assertEqual(SecurityValidator.validate_target_host("http://127.0.0.1:8080/test"), "127.0.0.1")

    def test_allowlist_blocks_unauthorized_external_targets(self):
        with self.assertRaises(SecurityViolationException):
            SecurityValidator.validate_target_host("malicious-target.com")

        with self.assertRaises(SecurityViolationException):
            SecurityValidator.validate_target_host("198.51.100.1")

    def test_empty_target_raises_violation(self):
        with self.assertRaises(SecurityViolationException):
            SecurityValidator.validate_target_host("")

    def test_command_injection_characters_rejected(self):
        with self.assertRaises(SecurityViolationException):
            SecurityValidator.sanitize_command_arguments("ping", ["127.0.0.1; rm -rf /"])

        with self.assertRaises(SecurityViolationException):
            SecurityValidator.sanitize_command_arguments("ping", ["127.0.0.1 && cat /etc/passwd"])

        with self.assertRaises(SecurityViolationException):
            SecurityValidator.sanitize_command_arguments("ping", ["`whoami`"])

    def test_unapproved_command_rejected(self):
        with self.assertRaises(SecurityViolationException):
            SecurityValidator.sanitize_command_arguments("bash", ["-c", "id"])

    def test_approved_command_passes(self):
        cmd, args = SecurityValidator.sanitize_command_arguments("ping", ["-c", "2", "127.0.0.1"])
        self.assertEqual(cmd, "ping")
        self.assertEqual(args, ["-c", "2", "127.0.0.1"])

    def test_load_test_limits_enforced(self):
        with self.assertRaises(SecurityViolationException):
            SecurityValidator.enforce_load_test_limits(
                requests=5000, concurrency=5, duration_sec=10, rps=10
            )

        with self.assertRaises(SecurityViolationException):
            SecurityValidator.enforce_load_test_limits(
                requests=100, concurrency=200, duration_sec=10, rps=10
            )

class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_path = self.temp_file.name
        self.temp_file.close()
        self.db = DatabaseManager(self.temp_path)

    def tearDown(self):
        if os.path.exists(self.temp_path):
            try:
                os.remove(self.temp_path)
            except Exception:
                pass

    def test_record_and_query_diagnostic(self):
        rec_id = self.db.record_diagnostic(
            target="127.0.0.1",
            port=80,
            status="OPEN",
            latency_ms=1.42,
            dns_time_ms=0.5,
            details={"test": True}
        )
        self.assertGreater(rec_id, 0)
        history = self.db.get_diagnostics_history(10)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["target"], "127.0.0.1")
        self.assertEqual(history[0]["status"], "OPEN")

    def test_record_and_query_dos_alert(self):
        rec_id = self.db.record_dos_alert(
            severity="CRITICAL",
            alert_type="IP_FLOOD",
            source_ip="203.0.113.5",
            request_rate=250.0,
            description="Test alert",
            recommendation="Block IP"
        )
        self.assertGreater(rec_id, 0)
        alerts = self.db.get_dos_alerts(10, severity="CRITICAL")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "203.0.113.5")

class TestSystemMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = SystemMonitor()

    def test_system_overview_structure(self):
        overview = self.monitor.get_system_overview()
        self.assertIn("platform", overview)
        self.assertIn("cpu", overview)
        self.assertIn("memory", overview)
        self.assertIn("disk", overview)
        self.assertIn("network", overview)

    def test_cpu_metrics(self):
        cpu = self.monitor.get_cpu_metrics()
        self.assertIn("percent", cpu)
        self.assertGreaterEqual(cpu["percent"], 0.0)

    def test_memory_metrics(self):
        mem = self.monitor.get_memory_metrics()
        self.assertIn("total_bytes", mem)
        self.assertIn("percent", mem)
        self.assertGreater(mem["total_bytes"], 0)

class TestDoSDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = DoSDetectionEngine(ip_concentration_pct=30.0)

    def test_parse_clf_log_line(self):
        line = '192.168.1.10 - - [10/Oct/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024'
        entry = self.engine.parse_log_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "192.168.1.10")
        self.assertEqual(entry.status_code, 200)

    def test_detect_ip_flood_anomaly(self):
        # Generate 60 requests from attacker IP and 10 from innocent
        logs = []
        for _ in range(60):
            logs.append('198.51.100.99 - - [10/Oct/2026:12:00:00 +0000] "GET /api HTTP/1.1" 200 512')
        for i in range(10):
            logs.append(f'10.0.0.{i} - - [10/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512')

        content = "\n".join(logs)
        alerts, metrics = self.engine.analyze_log_content(content)
        self.assertGreater(len(alerts), 0)
        top_alert = alerts[0]
        self.assertEqual(top_alert.source_ip, "198.51.100.99")
        self.assertIn(top_alert.severity, ("HIGH", "CRITICAL"))
        self.assertIn("iptables", top_alert.generated_rules)
        self.assertIn("198.51.100.99", top_alert.generated_rules["iptables"])

    def test_detect_error_storm(self):
        logs = []
        for _ in range(50):
            logs.append('192.168.1.50 - - [10/Oct/2026:12:00:00 +0000] "GET /login HTTP/1.1" 500 128')
        for _ in range(10):
            logs.append('10.0.0.1 - - [10/Oct/2026:12:00:00 +0000] "GET /data HTTP/1.1" 200 1024')
        content = "\n".join(logs)
        alerts, metrics = self.engine.analyze_log_content(content)
        error_alerts = [a for a in alerts if a.indicator_type == "ERROR_STORM"]
        self.assertEqual(len(error_alerts), 1)
        self.assertIn("error response ratio", error_alerts[0].description)

class TestConfig(unittest.TestCase):
    def test_config_target_allowed(self):
        cfg = Config()
        self.assertTrue(cfg.is_target_allowed("127.0.0.1"))
        self.assertTrue(cfg.is_target_allowed("localhost"))
        self.assertTrue(cfg.is_target_allowed("http://localhost:3000/api"))
        self.assertFalse(cfg.is_target_allowed("evil.example.com"))

class TestLoadTestLab(unittest.TestCase):
    def setUp(self):
        self.tester = LoadTestEngine()

    def test_unauthorized_target_rejected(self):
        with self.assertRaises(SecurityViolationException):
            self.tester.run_load_test(
                target_url="http://external-unauthorized.com",
                confirmed_authorized=True
            )

    def test_unconfirmed_authorization_rejected(self):
        with self.assertRaises(SecurityViolationException):
            self.tester.run_load_test(
                target_url="http://127.0.0.1:8000",
                confirmed_authorized=False
            )

    def test_dry_run_simulation(self):
        res = self.tester.run_load_test(
            target_url="http://127.0.0.1:8000",
            total_requests=25,
            concurrency=3,
            dry_run=True,
            confirmed_authorized=True
        )
        self.assertTrue(res.dry_run)
        self.assertGreater(res.p50_latency_ms, 0)
        self.assertEqual(res.failed_requests, 0)

class TestReportGenerator(unittest.TestCase):
    def test_generate_html_and_json_reports(self):
        reporter = ReportGenerator()
        html = reporter.generate_html_report(
            title="Unit Test Suite",
            diagnostics=[{"timestamp": "2026-10-11T12:00:00Z", "target": "127.0.0.1", "port": 80, "status": "OPEN", "latency_ms": 1.2}],
            dos_alerts=[{"severity": "HIGH", "alert_type": "IP_FLOOD", "description": "High rate", "recommendation": "Block"}]
        )
        self.assertIn("ROGUEBYTE", html)
        self.assertIn("127.0.0.1", html)

        json_rep = reporter.generate_json_report({"test_status": "PASS"})
        parsed = json.loads(json_rep)
        self.assertEqual(parsed["application"], "ROGUEBYTE Cybersecurity Workstation")

if __name__ == "__main__":
    unittest.main()
