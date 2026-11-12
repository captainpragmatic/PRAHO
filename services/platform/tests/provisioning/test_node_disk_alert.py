"""A full node disk aborts MariaDB and databases have no kernel cap, so operators are warned at 10% and 5% (ADR-0075)."""

import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import yaml
from django.conf import settings
from django.test import SimpleTestCase

PLAYBOOKS = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks"
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


class NodeDiskAlertTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        spec = importlib.util.spec_from_file_location("praho_disk_alert", PLAYBOOKS / "files/praho_disk_alert.py")
        cls.alert = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.alert)

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.state = self.root / "disk-alert.json"
        self.operators = self.root / "operators.json"
        self.operators.write_text(json.dumps(["ops@example.test"]))
        self.webmin = self.root / "webmin-config"
        self.webmin.write_text("webmin_email_to=root@example.test\n")
        self.sent = []

    def run_alert(self, free_percent, now=NOW):
        # 1000 usable blocks; reserved blocks exist and must not count as free.
        space = SimpleNamespace(f_blocks=1050, f_bfree=free_percent * 10 + 50, f_bavail=free_percent * 10, f_frsize=4096)
        with (
            patch.object(self.alert, "STATE", self.state),
            patch.object(self.alert, "OPERATORS", self.operators),
            patch.object(self.alert, "WEBMIN_CONFIG", self.webmin),
            patch.object(self.alert.os, "statvfs", return_value=space),
            patch.object(self.alert.socket, "gethostname", return_value="node-001.test"),
            patch.object(self.alert, "_send", side_effect=lambda to, message: self.sent.append((to, message))),
        ):
            self.alert.check(now=now)

    def subjects(self):
        return [message.splitlines()[0] for _to, message in self.sent]

    def test_free_space_is_measured_on_what_unprivileged_writers_can_use(self):
        space = SimpleNamespace(f_blocks=1050, f_bfree=150, f_bavail=100, f_frsize=4096)
        self.assertEqual(self.alert.free_percent(space), 10.0)

    def test_plenty_of_room_sends_nothing(self):
        self.run_alert(50)
        self.assertEqual(self.sent, [])

    def test_each_threshold_alerts_once_as_it_worsens(self):
        for free in (9, 8, 4, 3):
            self.run_alert(free)
        self.assertEqual(len(self.sent), 2)
        self.assertIn("10%", self.subjects()[0])
        self.assertIn("5%", self.subjects()[1])
        self.assertEqual(self.sent[0][0], ["ops@example.test"])

    def test_a_low_disk_is_repeated_daily(self):
        self.run_alert(8)
        self.run_alert(8, now=NOW + timedelta(hours=23))
        self.assertEqual(len(self.sent), 1)
        self.run_alert(8, now=NOW + timedelta(hours=25))
        self.assertEqual(len(self.sent), 2)

    def test_a_disk_that_improves_but_stays_low_is_still_reminded_daily(self):
        self.run_alert(4)
        self.run_alert(8, now=NOW + timedelta(hours=1))
        self.assertEqual(len(self.sent), 1)
        self.run_alert(8, now=NOW + timedelta(hours=25))
        self.assertEqual(len(self.sent), 2)
        self.assertIn("below 10%", self.subjects()[1])

    def test_falling_back_below_5_after_an_improvement_alerts_at_once(self):
        self.run_alert(4)
        self.run_alert(8, now=NOW + timedelta(hours=1))
        self.run_alert(4, now=NOW + timedelta(hours=2))
        self.assertEqual(len(self.sent), 2)
        self.assertIn("below 5%", self.subjects()[1])

    def test_recovery_is_reported_once(self):
        self.run_alert(4)
        self.run_alert(40)
        self.run_alert(41)
        self.assertEqual(len(self.sent), 2)
        self.assertIn("recovered", self.subjects()[1])

    def test_a_failed_send_is_retried_next_run(self):
        space = SimpleNamespace(f_blocks=1050, f_bfree=130, f_bavail=80, f_frsize=4096)
        with (
            patch.object(self.alert, "STATE", self.state),
            patch.object(self.alert, "OPERATORS", self.operators),
            patch.object(self.alert, "WEBMIN_CONFIG", self.webmin),
            patch.object(self.alert.os, "statvfs", return_value=space),
            patch.object(self.alert, "_send", side_effect=OSError("mailer down")),
            self.assertRaises(OSError),
        ):
            self.alert.check(now=NOW)
        self.assertFalse(self.state.exists())
        self.run_alert(8, now=NOW + timedelta(minutes=5))
        self.assertEqual(len(self.sent), 1)

    def test_before_handover_the_webmin_recipient_is_used(self):
        self.operators.unlink()
        self.run_alert(8)
        self.assertEqual(self.sent[0][0], ["root@example.test"])

    def test_no_recipient_is_a_failure_not_silence(self):
        self.operators.unlink()
        self.webmin.write_text("other=1\n")
        with self.assertRaisesRegex(ValueError, "recipient"):
            self.run_alert(8)

    def test_a_header_injecting_recipient_is_dropped(self):
        self.operators.write_text(json.dumps(["ops@example.test\nBcc: x@example.test", "real@example.test"]))
        self.run_alert(8)
        self.assertEqual(self.sent[0][0], ["real@example.test"])

    def test_the_timer_is_installed_on_every_play(self):
        tasks = yaml.safe_load((PLAYBOOKS / "virtualmin_usage_tasks.yml").read_text())
        by_name = {task.get("name"): task for task in tasks}
        script = by_name["Install the node free-space alert"]["ansible.builtin.copy"]
        self.assertEqual((script["src"], script["mode"]), ("files/praho_disk_alert.py", "0700"))
        service = by_name["Install the node free-space alert service"]["ansible.builtin.copy"]
        self.assertIn("ExecStart=/usr/bin/python3 /usr/local/libexec/praho_disk_alert.py", service["content"])
        self.assertIn("OnUnitActiveSec=", by_name["Install the node free-space alert timer"]["ansible.builtin.copy"]["content"])
        enable = by_name["Enable the node free-space alert timer"]["ansible.builtin.systemd"]
        self.assertEqual((enable["name"], enable["enabled"], enable["state"]), ("praho-disk-alert.timer", True, "started"))
        for name, task in by_name.items():
            if name and "free-space alert" in name:
                self.assertNotIn("when", task)
