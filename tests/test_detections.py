import os
import unittest

from log_analyzer import detections
from log_analyzer.parsers import load

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
LINUX = load(os.path.join(SAMPLES, "auth.log"), 2026)
WINDOWS = load(os.path.join(SAMPLES, "windows_security.csv"))


def rules(events):
    return [a.rule for a in detections.run_all(events)]


class ParserTests(unittest.TestCase):
    def test_linux_events_parsed(self):
        actions = [e.action for e in LINUX]
        self.assertEqual(actions.count("login_failed"), 9)
        self.assertEqual(actions.count("invalid_user"), 5)  # "Invalid user" duplicate lines are skipped
        self.assertIn("user_created", actions)

    def test_windows_events_parsed(self):
        self.assertEqual(sum(e.action == "login_failed" for e in WINDOWS), 6)
        self.assertEqual(WINDOWS[-3].ip, "")  # "-" is treated as no IP


class LinuxDetectionTests(unittest.TestCase):
    def setUp(self):
        self.alerts = detections.run_all(LINUX)
        self.names = [a.rule for a in self.alerts]

    def test_brute_force_from_attacker_ip(self):
        bf = [a for a in self.alerts if a.rule == "Brute force"]
        self.assertEqual([a.ip for a in bf], ["203.0.113.50"])

    def test_root_login_after_failures_is_high(self):
        hit = [a for a in self.alerts if a.rule == "Successful login after repeated failures"]
        self.assertEqual(len(hit), 1)
        self.assertEqual((hit[0].user, hit[0].severity), ("root", "High"))

    def test_password_spray(self):
        spray = [a for a in self.alerts if a.rule.startswith("Password spraying")]
        self.assertEqual(spray[0].ip, "198.51.100.77")

    def test_off_hours_and_new_account(self):
        self.assertIn("Off-hours login", self.names)
        self.assertIn("New account created", self.names)

    def test_single_typo_is_not_an_alert(self):
        # alice mistyped once at 16:20 then logged in: normal behaviour
        self.assertFalse(any(a.user == "alice" for a in self.alerts))


class WindowsDetectionTests(unittest.TestCase):
    def test_windows_rules(self):
        names = rules(WINDOWS)
        self.assertIn("Brute force", names)
        self.assertIn("Account added to an admin group", names)
        self.assertIn("New account created", names)


if __name__ == "__main__":
    unittest.main()
