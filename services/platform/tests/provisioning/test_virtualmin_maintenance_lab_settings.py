"""Each real service loads the same private local lab authority after its dev defaults."""

import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, override_settings


class MaintenanceLabSettingsTests(SimpleTestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="praho-maintenance-authority-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.authority = self.root / "authority.json"
        self.data = {"secret": secrets.token_urlsafe(48), "platform_port": 18870, "portal_port": 18871}
        self.write_authority()

    def write_authority(self) -> None:
        self.authority.write_text(json.dumps(self.data))
        self.authority.chmod(0o600)

    def load(self, service: str, *, enabled: bool = True) -> subprocess.CompletedProcess[str]:
        repo = Path(__file__).resolve().parents[4]
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "SYSTEMROOT", "TMPDIR", "LANG", "LC_ALL", "HOME"}
        }
        env.update(
            {
                "PRAHO_SKIP_DOTENV": "1",
                "VIRTUALMIN_MAINTENANCE_LAB": "1" if enabled else "0",
                "VIRTUALMIN_MAINTENANCE_AUTHORITY": str(self.authority),
                "VIRTUALMIN_LAB_DATABASE": str(self.root / "platform.sqlite3"),
            }
        )
        code = """
import json
import os
from pathlib import Path
from django.conf import settings
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.lab'
expected = json.loads(Path(os.environ['VIRTUALMIN_MAINTENANCE_AUTHORITY']).read_text())
secret = expected['secret']
assert settings.PLATFORM_API_SECRET == secret
assert settings.ALLOWED_HOSTS == ['127.0.0.1']
assert settings.SESSION_COOKIE_NAME == 'maintenance_lab_' + os.environ['LAB_TEST_ROLE']
if os.environ['LAB_TEST_ROLE'] == 'platform':
    assert settings.PORTAL_HMAC_MODE == 'enforce'
    assert json.loads(settings.PORTAL_HMAC_CREDENTIALS) == {'virtualmin-maintenance-lab': secret}
    assert settings.EMAIL_BACKEND == 'django.core.mail.backends.filebased.EmailBackend'
    assert Path(settings.EMAIL_FILE_PATH).resolve() == (Path(os.environ['VIRTUALMIN_MAINTENANCE_AUTHORITY']).parent / 'mail').resolve()
else:
    assert settings.PORTAL_ID == 'virtualmin-maintenance-lab'
    assert settings.PORTAL_HMAC_SECRET == secret
    assert settings.PLATFORM_API_BASE_URL == 'http://127.0.0.1:18870/api'
    assert Path(settings.DATABASES['default']['NAME']).resolve() == (Path(os.environ['VIRTUALMIN_MAINTENANCE_AUTHORITY']).parent / 'portal.sqlite3').resolve()
print('Private lab authority applied')
"""
        env["LAB_TEST_ROLE"] = service
        return subprocess.run(  # noqa: S603 -- current interpreter, fixed source and isolated local fixture paths
            [sys.executable, "-c", code],
            cwd=repo / "services" / service,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_platform_and_portal_apply_the_same_fresh_authority(self) -> None:
        for service in ("platform", "portal"):
            with self.subTest(service=service):
                result = self.load(service)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Private lab authority applied", result.stdout)
                self.assertNotIn(self.data["secret"], result.stdout + result.stderr)

    def test_both_services_refuse_a_group_readable_authority(self) -> None:
        self.authority.chmod(0o640)
        for service in ("platform", "portal"):
            with self.subTest(service=service):
                result = self.load(service)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("private maintenance lab authority", result.stderr)

    def test_both_services_refuse_ports_that_could_not_name_two_owned_listeners(self) -> None:
        for port in (0, True, "18870", 65536, self.data["portal_port"]):
            self.data["platform_port"] = port
            self.write_authority()
            for service in ("platform", "portal"):
                with self.subTest(port=port, service=service):
                    result = self.load(service)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("private maintenance lab authority", result.stderr)

    def test_portal_lab_settings_require_the_explicit_mode(self) -> None:
        result = self.load("portal", enabled=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private maintenance lab authority", result.stderr)


class MaintenanceLabCommandTests(SimpleTestCase):
    def test_explicit_fixture_command_requires_private_lab_mode(self) -> None:
        with (
            override_settings(SETTINGS_MODULE="config.settings.lab", DEBUG=True, VIRTUALMIN_MAINTENANCE_LAB=False),
            self.assertRaisesMessage(CommandError, "explicit private lab settings and command flag"),
        ):
            call_command("virtualmin_lab_runserver", "127.0.0.1:18870", maintenance_fixture=True, no_worker=True)

    def test_private_mode_refuses_the_default_broad_lab_worker(self) -> None:
        with (
            override_settings(SETTINGS_MODULE="config.settings.lab", DEBUG=True, VIRTUALMIN_MAINTENANCE_LAB=True),
            self.assertRaisesMessage(CommandError, "explicit private lab settings and command flag"),
        ):
            call_command("virtualmin_lab_runserver", "127.0.0.1:18870", no_worker=True)

    def test_private_mode_refuses_a_public_listener_before_startup(self) -> None:
        with (
            override_settings(
                SETTINGS_MODULE="config.settings.lab",
                DEBUG=True,
                VIRTUALMIN_MAINTENANCE_LAB=True,
                VIRTUALMIN_MAINTENANCE_PLATFORM_ADDRESS="127.0.0.1:18870",
                VIRTUALMIN_MAINTENANCE_MANIFEST="/nonexistent/manifest.json",
            ),
            self.assertRaisesMessage(CommandError, "exact owned loopback listener"),
        ):
            call_command("virtualmin_lab_runserver", "0.0.0.0:18870", maintenance_fixture=True, no_worker=True)
