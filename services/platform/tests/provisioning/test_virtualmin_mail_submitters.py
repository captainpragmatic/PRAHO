"""A complete native UID map grants only proven sender authority and swaps atomically."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

HELPER = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho_mail_submitters.py"


class NativeSubmitterMapTests(SimpleTestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("mail_submitters", HELPER)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.rows = [
            {
                "domain": "customer.example",
                "owner": "customer",
                "owner_uid": 1001,
                "enabled": True,
                "users": [
                    {"login": "reader.customer", "uid": 1002, "email": "reader@customer.example", "enabled": True}
                ],
            }
        ]

    def test_owner_webapp_own_domain_and_enabled_mailbox_are_scoped_without_a_fallback(self):
        result = self.module.render(self.rows, ["accounts.example"])
        self.assertIn(b"customer @customer.example\n", result)
        self.assertIn(b"reader.customer reader@customer.example\n", result)
        self.assertIn(b"root *\n", result)
        self.assertIn(b"postfix *\n", result)
        self.assertNotIn(b"static:", result)
        self.assertEqual(result.count(b"*"), 2)

    def test_disabled_domains_and_users_and_reserved_connection_names_never_grant_authority(self):
        self.rows[0]["users"][0]["enabled"] = False
        self.assertNotIn(b"reader.customer", self.module.render(self.rows, ["accounts.example"]))
        self.rows[0]["enabled"] = False
        self.assertNotIn(b"customer", self.module.render(self.rows, ["accounts.example"]))
        for name in ["accounts.example", "h1234567.accounts.example", "h1234567.old-accounts.example"]:
            self.rows[0].update(domain=name, enabled=True, users=[])
            self.assertNotIn(b"customer", self.module.render(self.rows, ["accounts.example", "old-accounts.example"]))

    def test_conflicting_uid_or_login_foreign_mailbox_and_overflow_refuse_whole_refresh(self):
        for row in [
            dict(self.rows[0], owner="other"),
            dict(self.rows[0], owner_uid=1003),
            dict(self.rows[0], domain="bad domain"),
        ]:
            with self.subTest(row=row), self.assertRaises(ValueError):
                self.module.render([*self.rows, row], ["accounts.example"])
        self.rows[0]["users"][0]["email"] = "reader@foreign.example"
        with self.assertRaises(ValueError):
            self.module.render(self.rows, ["accounts.example"])
        with self.assertRaises(ValueError):
            self.module.render([], [f"zone{i}.example" for i in range(65)])

    def replace_map(self, path, content, *, interrupt=False, private_umask=False):
        native = HELPER.with_name("praho-mail-native.pl")
        script = "BEGIN { *CORE::GLOBAL::rename = sub { die 'interrupted' }; } " if interrupt else ""
        script += (
            "require $ARGV[0]; umask(0077) if $ARGV[3]; virtual_server::replace_submitter_map($ARGV[1], $ARGV[2]);"
        )
        result = subprocess.run(  # noqa: S603  # Fixed repository Perl helper and private fixture arguments.
            ["/usr/bin/perl", "-e", script, str(native), str(path), content.decode(), str(int(private_umask))],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise OSError(result.stderr)

    def test_interrupted_replacement_preserves_previous_complete_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "senders"
            path.write_bytes(b"old-authority\n")
            with self.assertRaises(OSError):
                self.replace_map(path, b"new-authority\n", interrupt=True)
            self.assertEqual(path.read_bytes(), b"old-authority\n")
            self.assertEqual(list(Path(directory).iterdir()), [path])
            self.replace_map(path, b"new-authority\n")
            self.assertEqual(path.read_bytes(), b"new-authority\n")

    def test_private_worker_umask_does_not_make_public_identity_map_unreadable_to_postdrop(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "senders"
            self.replace_map(path, b"root *\npostfix *\n", private_umask=True)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_native_output_suppression_preserves_real_child_pipe_and_public_receipt(self):
        native = HELPER.with_name("praho-mail-native.pl")
        script = """require $ARGV[0];
my $value = virtual_server::run_native_silenced(sub {
 print "native-private-output";
 my $pid = IPC::Open2::open2(my $reader, my $writer, '/usr/bin/python3', '-c', "print('renderer-safe')");
 close($writer); local $/; my $output = <$reader>; close($reader); waitpid($pid, 0);
 return $output // 'EMPTY';
}); print 'receipt=' . $value;"""
        result = subprocess.run(  # noqa: S603  # Fixed repository helper and local Python pipe fixture.
            ["/usr/bin/perl", "-e", script, str(native)], capture_output=True, text=True, check=True
        )
        self.assertEqual(result.stdout, "receipt=renderer-safe\n")
        self.assertNotIn("native-private", result.stdout + result.stderr)

    def test_disabling_parent_revokes_child_and_alias_submitters_before_native_deletion(self):
        native = HELPER.with_name("praho-mail-native.pl")
        rows = {"1": {"id": "1"}, "2": {"id": "2", "parent": "1"}, "3": {"id": "3", "alias": "2"}}
        script = """require $ARGV[0]; my $rows = JSON::PP::decode_json($ARGV[1]);
my $value; my $ok = eval { $value = virtual_server::submitter_enabled($rows->{'3'}, $rows); 1; };
print JSON::PP::encode_json({ok => $ok ? JSON::PP::true() : JSON::PP::false(),
 enabled => $value ? JSON::PP::true() : JSON::PP::false()});"""
        for changes, expected_ok, expected_enabled in [
            ({}, True, True),
            ({"disabled": "unix"}, True, False),
            ({"parent": "missing"}, False, False),
            ({"parent": "3"}, False, False),
        ]:
            with self.subTest(changes=changes):
                rows["1"] = {"id": "1", **changes}
                result = subprocess.run(  # noqa: S603  # Fixed helper and bounded native graph fixture.
                    ["/usr/bin/perl", "-e", script, str(native), json.dumps(rows)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(json.loads(result.stdout), {"ok": expected_ok, "enabled": expected_enabled})
