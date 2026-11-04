"""Actual native vault, field encryption and session cookies are VM-key isolated."""

import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from tests.helpers.native_authority import make_authority, native_settings

ROUNDTRIP = r"""
import base64, json, sys
import django
django.setup()
from apps.common.credential_vault import CredentialVault
from apps.common.encryption import encrypt_sensitive_data, decrypt_sensitive_data
from apps.users.session_backend import SessionStore
vault = CredentialVault()
supplied = json.loads(sys.argv[1])
if not supplied:
    print(json.dumps({
        'field': encrypt_sensitive_data('native fixture secret'),
        'vault': base64.b64encode(vault._encrypt_data(b'native vault secret', aad=b'native-test')).decode(),
        'session': SessionStore().encode({'native': 'fixture session'}),
    }))
else:
    outcomes = {}
    try:
        outcomes['field'] = decrypt_sensitive_data(supplied['field']) == 'native fixture secret'
    except Exception:
        outcomes['field'] = False
    try:
        outcomes['vault'] = vault._decrypt_data(base64.b64decode(supplied['vault']), aad=b'native-test') == b'native vault secret'
    except Exception:
        outcomes['vault'] = False
    outcomes['session'] = SessionStore().decode(supplied['session']) == {'native': 'fixture session'}
    print(json.dumps(outcomes))
"""


class NativeKeyIsolationTests(SimpleTestCase):
    def test_reencoding_the_same_ssh_private_key_cannot_silently_change_derived_crypto_keys(self):
        with TemporaryDirectory() as directory:
            authority = make_authority(Path(directory))
            native_settings(authority)
            parsed = serialization.load_ssh_private_key(authority.key, password=None)
            reencoded = parsed.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
            )
            self.assertNotEqual(reencoded, authority.key)
            path = authority.path.parent / (authority.manifest["run"] + ".key")
            path.write_bytes(reencoded)
            try:
                with self.assertRaisesRegex(ImproperlyConfigured, "crypto identity mismatch"):
                    native_settings(authority)
            finally:
                path.write_bytes(authority.key)

    def test_old_bound_fixture_without_key_profile_refuses_and_marker_mismatch_never_rekeys(self):
        with TemporaryDirectory() as directory:
            authority = make_authority(Path(directory))
            value = json.loads(authority.path.read_bytes())
            value["platform_fixture"] = {"database": "old-native-test-keys"}
            authority.path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ImproperlyConfigured, "fresh isolated fixture database"):
                native_settings(authority)
            marker = authority.path.parent / (authority.manifest["run"] + ".native-crypto.json")
            self.assertFalse(marker.exists())
            value.pop("platform_fixture")
            authority.path.write_text(json.dumps(value))
            native_settings(authority)
            original = marker.read_bytes()
            changed = json.loads(original)
            changed["database"] = "different_native_database"
            marker.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ImproperlyConfigured, "crypto identity mismatch"):
                native_settings(authority, cleanup=True)
            self.assertEqual(json.loads(marker.read_bytes())["database"], "different_native_database")

    def test_fresh_process_same_original_vm_key_roundtrips_and_other_vm_refuses_all_three_consumers(self):
        root = Path(__file__).resolve().parents[4]
        with TemporaryDirectory() as directory:
            first_root, second_root = Path(directory) / "first", Path(directory) / "second"
            first_root.mkdir()
            second_root.mkdir()
            first, second = make_authority(first_root), make_authority(second_root)

            def execute(manifest, supplied):
                environment = {
                    key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "LANG", "TMPDIR"}
                }
                environment.update(
                    {
                        "PRAHO_NATIVE_LAB": "1",
                        "DB_NAME": "praho_native_crypto_test",
                        "NATIVE_VM_MANIFEST": str(manifest.path),
                        "DJANGO_SETTINGS_MODULE": "config.settings.native",
                        "PYTHONPATH": str(root / "services/platform"),
                    }
                )
                result = subprocess.run(  # noqa: S603 -- exact interpreter/source, synthetic cipher payload and owned manifest.
                    [sys.executable, "-c", ROUNDTRIP, json.dumps(supplied)],
                    cwd=root / "services/platform",
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout.strip().splitlines()[-1])

            encrypted = execute(first, {})
            self.assertEqual(execute(first, encrypted), {"field": True, "vault": True, "session": True})
            self.assertEqual(execute(second, encrypted), {"field": False, "vault": False, "session": False})
