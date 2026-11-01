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

    def load(self, service: str, *, enabled: bool = True, code_suffix: str = "") -> subprocess.CompletedProcess[str]:
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
        code += code_suffix
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

    def test_owned_platform_serializes_a_ledger_read_upgrade_against_an_autocommit_writer(self) -> None:
        result = self.load(
            "platform",
            code_suffix="""
import threading
import sqlite3
import django
from django.db import connections, transaction

django.setup()
with connections['default'].cursor() as cursor:
    cursor.execute('CREATE TABLE ledger_canary (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)')
    cursor.executemany('INSERT INTO ledger_canary VALUES (%s, %s)', [(1, 10), (2, 20)])
connections['default'].close()

reader_ready = threading.Event()
writer_attempted = threading.Event()
writer_reserved = threading.Event()
errors = {}
attempts = {'ledger': 0, 'http': 0}

def wait_for(event, label):
    if not event.wait(10):
        raise AssertionError('Timed out waiting for ' + label)

def ledger():
    connection = connections['default']
    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute('SELECT value FROM ledger_canary WHERE id = 1')
                assert cursor.fetchone() == (10,)
                # An independent, nonblocking writer must already be excluded by
                # the real ledger transaction, before HTTP competes for the lock.
                probe = sqlite3.connect(settings.DATABASES['default']['NAME'], timeout=0)
                try:
                    try:
                        probe.execute('BEGIN IMMEDIATE')
                    except sqlite3.OperationalError as error:
                        assert str(error) == 'database is locked', str(error)
                    else:
                        probe.rollback()
                        raise AssertionError('Ledger SELECT did not retain the SQLite writer reservation')
                finally:
                    probe.close()
                reader_ready.set()
                wait_for(writer_attempted, 'competing autocommit UPDATE')
                attempts['ledger'] += 1
                cursor.execute('UPDATE ledger_canary SET value = value + 1 WHERE id = 1')
    except Exception as error:
        errors['ledger'] = type(error).__name__ + ': ' + str(error)
    finally:
        reader_ready.set()
        connection.close()

def http_writer():
    connection = connections['default']
    try:
        wait_for(reader_ready, 'ledger SELECT')
        connection.ensure_connection()
        assert connection.get_autocommit()
        def reserved():
            writer_reserved.set()
            return 1
        def entered(statement):
            if statement.startswith('UPDATE ledger_canary'):
                writer_attempted.set()
        connection.connection.create_function('write_reserved', 0, reserved)
        connection.connection.set_trace_callback(entered)
        with connection.cursor() as cursor:
            attempts['http'] += 1
            cursor.execute('UPDATE ledger_canary SET value = value + write_reserved() WHERE id = 2')
    except Exception as error:
        errors['http'] = type(error).__name__ + ': ' + str(error)
    finally:
        connection.close()

threads = [threading.Thread(target=ledger), threading.Thread(target=http_writer)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join(12)
assert not any(thread.is_alive() for thread in threads), 'A canary connection failed to terminate'
assert errors == {}, errors
assert attempts == {'ledger': 1, 'http': 1}, attempts
assert writer_reserved.is_set(), 'Competing UPDATE never obtained its reservation'
with connections['default'].cursor() as cursor:
    cursor.execute('SELECT value FROM ledger_canary ORDER BY id')
    assert cursor.fetchall() == [(11,), (21,)]
connections['default'].close()
print('Both private ledger writes committed once without retry')
""",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Both private ledger writes committed once without retry", result.stdout)

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
