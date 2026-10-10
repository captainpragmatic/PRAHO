"""Every production Compose stack runs the Django-Q worker beside Platform.

Without it nothing queued ever runs: password-reset mails, invoice and provisioning jobs, and the
scheduled tasks stay in the queue while every request still answers as if they had been sent.
"""

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
STACKS = ("single-server", "platform-only", "container-service")


class ComposeTaskWorkerTests(unittest.TestCase):
    def test_each_stack_runs_the_worker_with_platforms_configuration(self) -> None:
        for stack in STACKS:
            with self.subTest(stack=stack):
                services = yaml.safe_load((ROOT / f"deploy/docker-compose.{stack}.yml").read_text())["services"]
                platform, worker = services["platform"], services["qcluster"]
                self.assertEqual(worker["command"], ["python", "manage.py", "qcluster"])
                self.assertEqual(worker["image"], platform["image"])
                for key in ("env_file", "environment", "volumes"):
                    self.assertEqual(worker.get(key), platform.get(key), key)
                # Platform's container runs the migrations; the worker must not race it.
                self.assertEqual(worker["depends_on"], {"platform": {"condition": "service_healthy"}})
                self.assertEqual(worker["restart"], "unless-stopped")
                self.assertNotIn("ports", worker)
                self.assertNotIn("healthcheck", worker)
                self.assertEqual(worker.get("networks"), platform.get("networks"))
