import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

from auth_analyzer import analyze, read_events


class AnalyzerTests(unittest.TestCase):
    sample = """Aug 10 09:00:01 app sshd[1]: Failed password for admin from 203.0.113.44 port 22 ssh2
Aug 10 09:01:01 app sshd[2]: Failed password for admin from 203.0.113.44 port 22 ssh2
Aug 10 09:02:01 app sshd[3]: Failed password for admin from 203.0.113.44 port 22 ssh2
Aug 10 09:03:01 app sshd[4]: Failed password for admin from 203.0.113.44 port 22 ssh2
Aug 10 09:04:01 app sshd[5]: Failed password for admin from 203.0.113.44 port 22 ssh2
Aug 10 09:05:01 app sshd[6]: Accepted password for admin from 203.0.113.44 port 22 ssh2
Aug 10 11:00:01 app sshd[7]: Accepted password for admin from 198.51.100.7 port 22 ssh2
"""

    def test_detects_expected_rules(self):
        events, ignored = read_events(io.StringIO(self.sample), 2026)
        rules = {alert.rule for alert in analyze(events)}
        self.assertEqual(ignored, 0)
        self.assertTrue({"multiple_failed_login_attempts", "brute_force_source", "targeted_account_attack", "success_after_failures", "successful_login_from_new_source"} <= rules)

    def test_json_cli_output(self):
        root = Path(__file__).parent
        result = subprocess.run([sys.executable, str(root / "auth_analyzer.py"), str(root / "sample_auth.log"), "--json"], check=True, capture_output=True, text=True)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["events"], 19)
        self.assertGreater(len(payload["alerts"]), 0)


if __name__ == "__main__":
    unittest.main()
