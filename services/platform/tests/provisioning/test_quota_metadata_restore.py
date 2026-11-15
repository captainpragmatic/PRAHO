"""The quota metadata child restores exactly the journalled fields, under the same lane and domain locks (#776).

The real Perl script runs against a stubbed Virtualmin library; only root identity and native paths are
substituted. A late storage refusal relies on this restore before the lane may record `refused`.
"""

import fcntl
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from django.test import SimpleTestCase

SOURCE = Path(__file__).resolve().parents[2] / "infrastructure/ansible/playbooks/files/praho-quota-metadata.pl"

NATIVE = r"""
use JSON::PP ();
our $fixture_root = $ENV{'PRAHO_NATIVE_FIXTURE'};
sub _domain_file { return "$fixture_root/domain.json"; }
sub get_domain {
    open(my $f, '<', _domain_file()) or return undef;
    local $/; my $d = JSON::PP::decode_json(<$f>); close $f;
    return $d->{'id'} eq $_[0] ? $d : undef;
}
sub save_domain {
    open(my $f, '>', _domain_file()) or return 0;
    print $f JSON::PP->new->canonical->encode($_[0]); close $f or return 0;
    return 1;
}
sub lock_domain { open(my $f, '>>', "$fixture_root/locks") or die; print $f "lock $_[0]\n"; close $f; }
sub unlock_domain { open(my $f, '>>', "$fixture_root/locks") or die; print $f "unlock $_[0]\n"; close $f; }
1;
"""


class QuotaMetadataRestoreTests(SimpleTestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.native = self.root / "native"
        self.native.mkdir()
        (self.native / "virtual-server-lib.pl").write_text(NATIVE)
        self.installation = str(uuid4())
        self.request = {
            "token": str(uuid4()),
            "generation": 3,
            "identity": {
                "installation": self.installation,
                "domain_id": "12345",
                "domain": "shop.test",
                "uid": 1001,
                "gid": 1001,
            },
            "disk_limit_kib": 1024,
            "bandwidth_limit_bytes": 0,
        }
        self.scope = self.root / "quotas" / self.installation / "12345"
        self.scope.mkdir(parents=True)
        digest = hashlib.sha256(json.dumps(self.request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.state = {"generation": 3, "token": self.request["token"], "digest": digest, "phase": "running"}
        (self.scope / "current.json").write_text(json.dumps(self.state))
        # What the apply child left behind: the new limits and the enforced policy, plus an unrelated field.
        self.domain = {
            "id": "12345",
            "dom": "shop.test",
            "uid": "1001",
            "gid": "1001",
            "quota": "1024",
            "uquota": "1024",
            "bw_limit": "0",
            "bw_no_disable": "1",
            "letsencrypt_email": "2",
            "home": "/home/shop",
        }
        self.write_domain(self.domain)
        self.lock = self.root / "run" / "chain-12345.lock"
        self.lock.parent.mkdir()
        self.lock.touch(mode=0o600)
        self.lock.chmod(0o600)  # The script refuses a lane lock any other user could open.
        source = SOURCE.read_text()
        for old, new in (
            ("unless $> == 0 &&", "unless 1 &&"),
            ("$held[4] == 0 &&", "1 &&"),
            ("'/run/praho/chain-'", f"'{self.lock.parent}/chain-'"),
            ("'/var/lib/praho/quotas/'", f"'{self.root}/quotas/'"),
            ("'/usr/share/webmin/virtual-server'", f"'{self.native}'"),
            ("'/usr/local/lib/praho/praho-notification-policy.pl'", f"'{self.root}/policy.pl'"),
        ):
            self.assertIn(old, source)
            source = source.replace(old, new)
        self.script = self.root / "metadata.pl"
        self.script.write_text(source)
        # The enforced policy the apply child also writes, as the real adapter does for a non-native node.
        (self.root / "policy.pl").write_text(
            "package virtual_server;\n"
            "sub praho_enforce_resource_policy { $_[0]->{'bw_no_disable'} = 1; }\n"
            "sub praho_enforce_domain_notifications { $_[0]->{'letsencrypt_email'} = 2; }\n1;\n"
        )
        # The lane lock is held once for the whole test, as the coordinator holds it for one application.
        self.descriptor = os.open(self.lock, os.O_WRONLY)
        self.addCleanup(os.close, self.descriptor)
        fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def write_domain(self, domain):
        (self.root / "domain.json").write_text(json.dumps(domain))

    def read_domain(self):
        return json.loads((self.root / "domain.json").read_text())

    def after(self):
        """What the apply child left: the image a restore must still find before it may write."""
        return {key: self.domain.get(key) for key in ("quota", "uquota", "bw_limit", "bw_no_disable", "letsencrypt_email")}

    def restore(self, before, *, request=None, mode="restore", expected=None):
        descriptor = self.descriptor
        payload = json.dumps(
            {"request": request or self.request, "restore": before, "expected": expected or self.after()}
            if mode != "apply"
            else (request or self.request)
        )
        return subprocess.run(  # noqa: S603 -- The repository's own script, private fixture paths.
            ["/usr/bin/perl", str(self.script), str(descriptor), *([] if mode == "apply" else [mode])],
            input=payload,
            capture_output=True,
            text=True,
            pass_fds=(descriptor,),
            env={**os.environ, "PRAHO_NATIVE_FIXTURE": str(self.root)},
            timeout=30,
            check=False,
        )

    def refused(self, result, reason):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(reason, result.stderr)
        self.assertEqual(self.read_domain(), self.domain)

    def before(self, **changes):
        return {
            "quota": "2048",
            "uquota": "2048",
            "bw_limit": None,
            "bw_no_disable": "1",
            "letsencrypt_email": "2",
            **changes,
        }

    def test_the_journalled_fields_are_restored_exactly_and_nothing_else_changes(self):
        result = self.restore(self.before())
        self.assertEqual(result.returncode, 0, result.stderr)
        domain = self.read_domain()
        self.assertEqual(domain["quota"], "2048")
        self.assertEqual(domain["uquota"], "2048")
        self.assertNotIn("bw_limit", domain)  # Absent before, so absent again.
        self.assertEqual(domain["home"], "/home/shop")
        self.assertEqual((self.root / "locks").read_text(), "lock 12345\nunlock 12345\n")

    def test_only_the_five_journalled_fields_are_accepted(self):
        for before in (
            {**self.before(), "home": "/elsewhere"},
            {key: value for key, value in self.before().items() if key != "quota"},
        ):
            with self.subTest(keys=sorted(before)):
                self.refused(self.restore(before), "Invalid quota metadata restore")

    def test_a_value_that_could_inject_another_field_is_refused(self):
        for value in ("2048\nhome=/elsewhere", "x" * 300, ["2048"], {"quota": "1"}, True):
            with self.subTest(value=value):
                self.refused(self.restore(self.before(quota=value)), "Invalid quota metadata restore value")

    def test_a_restore_needs_the_same_running_application(self):
        for state in ({**self.state, "phase": "completed"}, {**self.state, "token": str(uuid4())}):
            with self.subTest(state=state["phase"]):
                (self.scope / "current.json").write_text(json.dumps(state))
                self.refused(self.restore(self.before()), "Quota application generation changed")
        (self.scope / "current.json").write_text(json.dumps(self.state))
        (self.scope / f"cancelled-{self.request['token']}.json").write_text("{}")
        self.refused(self.restore(self.before()), "Quota application cancelled")

    def test_a_changed_owner_is_never_restored_over(self):
        self.domain = {**self.domain, "uid": "1002"}
        self.write_domain(self.domain)
        # The owner check runs inside the domain lock's eval, which reports one generic failure.
        self.refused(self.restore(self.before()), "Native quota metadata did not complete")

    def test_an_unknown_mode_is_refused(self):
        self.refused(self.restore(self.before(), mode="rewrite"), "Root quota metadata operation required")

    def test_a_field_changed_since_the_application_is_never_restored_over(self):
        # An administrator changed the quota after the apply child: restoring would overwrite that change.
        self.domain = {**self.domain, "quota": "4096"}
        self.write_domain(self.domain)
        self.refused(self.restore(self.before(), expected={**self.after(), "quota": "1024"}), "Native quota metadata did not complete")

    def test_the_expected_image_must_name_exactly_the_five_fields(self):
        after = self.after()
        del after["quota"]
        self.refused(self.restore(self.before(), expected=after), "Invalid quota metadata restore")

    def test_the_apply_child_reports_what_it_saw_and_left_under_the_domain_lock(self):
        before = {**self.domain, "quota": "2048", "uquota": "2048", "letsencrypt_email": "owner@example.test"}
        del before["bw_limit"]
        self.write_domain(before)
        result = self.restore(None, mode="apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [line for line in result.stdout.splitlines() if line.startswith("PRAHO_QUOTA_METADATA ")]
        self.assertEqual(len(lines), 1, result.stdout)
        images = json.loads(lines[0].removeprefix("PRAHO_QUOTA_METADATA "))
        self.assertEqual(
            images["before"],
            {"quota": "2048", "uquota": "2048", "bw_limit": None, "bw_no_disable": "1", "letsencrypt_email": "owner@example.test"},
        )
        self.assertEqual(
            images["after"],
            {"quota": "1024", "uquota": "1024", "bw_limit": "0", "bw_no_disable": "1", "letsencrypt_email": "2"},
        )
