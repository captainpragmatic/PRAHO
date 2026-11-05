"""Native mail ownership covers OS quota warnings and explicit backup recipients."""

import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.test import SimpleTestCase


class HostingMailCompletenessTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.files = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files"
        cls.fixtures = Path(settings.BASE_DIR) / "tests/fixtures"
        stock = json.loads((cls.fixtures / "quota_4_09_cron_daily.json").read_text())
        cls.stock_cron = stock["source"]
        assert (
            hashlib.sha256(cls.stock_cron.encode()).hexdigest()
            == stock["sha256"]
            == "e34d72322f0a58df9d06a0bfd68709efc4801964a8c9b64a7bc0b6e19d9e0f35"
        )
        spec = importlib.util.spec_from_file_location("mail_completeness_native", cls.files / "praho_hosting_node.py")
        cls.native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.native)

    def _read_enabled_os_quota(self, path, **kwargs):
        if path == Path("/etc/default/quota"):
            return 'run_warnquota="true"\nRPCRQUOTADOPTS=\n'
        if path == Path("/etc/cron.daily/quota"):
            return self.stock_cron
        if path == Path("/etc/machine-id"):
            return "f3dc92d50ac14de0b663f7daab29960a"
        if path.name == "operators.json":
            return "[]"
        raise FileNotFoundError(path)

    def test_native_inspection_does_not_certify_enabled_stock_os_customer_quota_mail(self):
        inventory = {
            "evidence": {
                "emitters": {"quota_warnings": True},
                "operator_alerts_preserved": True,
                "tenant_mail_preserved": True,
            },
            "inventory_digest": "a" * 64,
        }
        with (
            patch.object(self.native, "_read", side_effect=self._read_enabled_os_quota),
            patch.object(self.native, "_run", return_value=json.dumps(inventory)),
            patch.dict("sys.modules", {"praho_quota_native": None}),
        ):
            result = self.native.inspect("a" * 64)
        self.assertFalse(result["notifications"]["emitters"]["os_quota_warnings"])

    def test_handover_refuses_enabled_os_warning_before_changing_virtualmin_policy(self):
        with (
            patch.object(self.native, "_read", side_effect=self._read_enabled_os_quota),
            patch.object(self.native, "_write"),
            patch.object(self.native, "_run") as native_command,
            patch.object(self.native, "_apply_notification_source_patches") as source_write,
            patch.object(self.native, "_emitters_idle"),
            self.assertRaisesRegex(ValueError, "quota"),
        ):
            self.native._notification_apply({"operator_emails": []}, 3, replace=True)
        source_write.assert_not_called()
        native_command.assert_not_called()

    def _os_policy(self, defaults, *, cron=None):
        values = {
            "/etc/default/quota": defaults,
            "/etc/cron.daily/quota": cron or self.stock_cron,
        }

        def read(path):
            value = values[str(path)]
            if isinstance(value, Exception):
                raise value
            return value

        with patch.object(self.native, "_read", side_effect=read):
            return self.native.os_quota_notification_inventory()

    def test_disabled_stock_os_policy_is_recognized_without_executing_shell(self):
        stock = (self.fixtures / "quota_4_09_default.txt").read_text()
        self.assertTrue(self._os_policy(stock)[0])
        self.assertTrue(
            self._os_policy('run_warnquota="false" # approved disabled route\nRPCRQUOTADOPTS="-p 123"\n')[0]
        )
        for unknown in (
            'run_warnquota="true"\n',
            'run_warnquota="$(touch /nonexistent-fixture-command)"\n',
            "run_warnquota=false; /usr/sbin/warnquota -ug\n",
            "run_warnquota=false\nrun_warnquota=true\n",
            'RPCRQUOTADOPTS=""\n',
            PermissionError("unreadable defaults"),
        ):
            with self.subTest(unknown=unknown):
                self.assertFalse(self._os_policy(unknown)[0])
        self.assertFalse(self._os_policy(stock, cron="unknown cron route\n")[0])

    def test_os_route_and_disabled_configuration_changes_bind_the_inventory_digest(self):
        first = self._os_policy("run_warnquota=false\n")
        second = self._os_policy("run_warnquota=false\n# reviewed change\n")
        self.assertTrue(first[0] and second[0])
        self.assertNotEqual(first[1], second[1])
        self.assertNotEqual(first[1], self._os_policy("run_warnquota=false\n", cron="unknown\n")[1])

    def test_shell_word_hash_and_non_lf_separators_cannot_hide_enabled_warnings(self):
        # These are assignments and a shell builtin only: execute the actual
        # interpreter grammar without sourcing any host configuration.
        for disabled in ("false", "'false'", '"false"', "false\r", "false\v", "false\f", "false\u2028"):
            defaults = f"run_warnquota={disabled}#disabled; run_warnquota=true\n"
            with self.subTest(disabled=disabled):
                result = subprocess.run(
                    ["/bin/sh"],
                    input=defaults + 'printf "%s" "$run_warnquota"\n',
                    capture_output=True,
                    text=True,
                    check=False,
                    env={"PATH": "/usr/bin:/bin"},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "true")
                self.assertFalse(self._os_policy(defaults)[0])

    def test_only_horizontal_shell_whitespace_is_accepted_outside_quoted_values(self):
        for whitespace in ("\r", "\v", "\f", "\u0085", "\u00a0", "\u2028", "\u2029"):
            for defaults in (f"{whitespace}run_warnquota=false\n", f"run_warnquota=false{whitespace}\n"):
                with self.subTest(defaults=defaults):
                    self.assertFalse(self._os_policy(defaults)[0])

    def test_space_tab_comments_and_quoted_hash_values_remain_supported(self):
        for defaults in (
            "\t run_warnquota=false\t # approved disabled route\n",
            "run_warnquota='false' \t# approved disabled route\n",
            'run_warnquota="false"\t\nRPCRQUOTADOPTS="literal#value"\n',
            " \t# comment without assignments\nrun_warnquota=\n",
        ):
            with self.subTest(defaults=defaults):
                self.assertTrue(self._os_policy(defaults)[0])

    def test_protected_source_read_preserves_exact_newline_bytes_for_stock_fingerprints(self):
        with TemporaryDirectory() as directory:
            source = Path(directory).resolve() / "cron"
            original = self.stock_cron.replace("\n", "\r\n").encode()
            source.write_bytes(original)
            source.chmod(0o600)
            real_stat = os.fstat

            def root_metadata(descriptor):
                info = list(real_stat(descriptor))
                info[4] = 0
                return os.stat_result(info)

            with patch.object(self.native.os, "fstat", side_effect=root_metadata):
                read = self.native._read(source)
            self.assertEqual(read.encode(), original)
            self.assertFalse(self._os_policy("run_warnquota=false\n", cron=read)[0])

    def test_actual_inspection_digest_binds_os_configuration_drift(self):
        inventory = {"evidence": {"emitters": {}}, "inventory_digest": "a" * 64}
        results = []
        for defaults in ("run_warnquota=false\n", "run_warnquota=false\n# operator review\n"):

            def read(path, value=defaults, **kwargs):
                return value if path == Path("/etc/default/quota") else self._read_enabled_os_quota(path)

            with (
                patch.object(self.native, "_read", side_effect=read),
                patch.object(self.native, "_run", return_value=json.dumps(inventory)),
                patch.dict("sys.modules", {"praho_quota_native": None}),
            ):
                results.append(self.native.inspect("a" * 64))
        self.assertTrue(all(item["notifications"]["emitters"]["os_quota_warnings"] for item in results))
        self.assertNotEqual(results[0]["notification_inventory_digest"], results[1]["notification_inventory_digest"])

    def _inspect_restored_acme(self, *, guarded, marker="platform\n", domain_flag=0, suffix=""):
        status = (self.fixtures / "virtualmin_existing_monitor_8_3.pl").read_text()
        ssl = (self.fixtures / "virtualmin_acme_notification_8_3.pl").read_text()
        if guarded:
            status, ssl = self.native.notification_source_patches(status, ssl)
        values = {
            Path("/usr/share/webmin/virtual-server/feature-status.pl"): status,
            Path("/usr/share/webmin/virtual-server/feature-ssl.pl"): ssl + suffix,
            self.native.STATE / "notification-owner": marker,
            Path("/etc/default/quota"): "run_warnquota=false\n",
        }

        def read(path, **kwargs):
            return values[path] if path in values else self._read_enabled_os_quota(path)

        # The native adapter independently observes restored per-domain settings.
        inventory = {"evidence": {"emitters": {"acme_owners": domain_flag == 2}}, "inventory_digest": "a" * 64}
        with (
            patch.object(self.native, "_read", side_effect=read),
            patch.object(self.native, "_run", return_value=json.dumps(inventory)),
            patch.dict("sys.modules", {"praho_quota_native": None}),
        ):
            return self.native.inspect("a" * 64)

    def test_guarded_old_archive_owner_flag_is_safe_without_rewriting_its_domain(self):
        result = self._inspect_restored_acme(guarded=True)
        self.assertTrue(result["notifications"]["emitters"]["acme_owners"])

    def test_domain_flag_alone_never_certifies_a_missing_or_unknown_acme_guard(self):
        for guarded, marker in ((False, "platform\n"), (True, "unknown\n")):
            with self.subTest(guarded=guarded, marker=marker):
                result = self._inspect_restored_acme(guarded=guarded, marker=marker, domain_flag=2)
                self.assertFalse(result["notifications"]["emitters"]["acme_owners"])

    def test_actual_inspection_digest_binds_native_source_bytes(self):
        first = self._inspect_restored_acme(guarded=True)
        second = self._inspect_restored_acme(guarded=True, suffix="\n# qualified source change\n")
        self.assertTrue(second["notifications"]["emitters"]["acme_owners"])
        self.assertNotEqual(first["notification_inventory_digest"], second["notification_inventory_digest"])

    def test_actual_stock_daily_route_invokes_user_and_group_warning_boundary(self):
        # Exact packaged cron; only fixed absolute filesystem paths are relocated.
        # The native warnquota/kernel boundary is a recording sentinel, not a denial/mail proof.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            defaults, fstab, warning, calls = (root / name for name in ("defaults", "fstab", "warnquota", "calls"))
            defaults.write_text('run_warnquota="true"\n')
            fstab.write_text("UUID=fixture / ext4 defaults,usrquota,grpquota 0 1\n")
            warning.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$WARNQUOTA_CALLS"\n')
            warning.chmod(0o700)
            source = self.stock_cron
            for old, new in (("/etc/default/quota", defaults), ("/etc/fstab", fstab), ("/usr/sbin/warnquota", warning)):
                source = source.replace(old, str(new))
            result = subprocess.run(
                ["/bin/sh"],
                input=source,
                capture_output=True,
                text=True,
                check=False,
                env={"PATH": "/usr/bin:/bin", "WARNQUOTA_CALLS": str(calls)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls.read_text().splitlines(), ["-ug"])
            self.assertFalse(self._os_policy(defaults.read_text())[0])

    def test_running_warnquota_is_an_emitter_that_handover_must_drain(self):
        self.assertTrue(self.native.native_emitter_command(b"/usr/sbin/warnquota\0-ug\0"))
        self.assertFalse(self.native.native_emitter_command(b"/usr/sbin/quota_nld\0-F\0"))

    def test_active_os_mailer_is_observed_until_exit_and_timeout_retains_the_hold(self):
        process = MagicMock()
        process.name = str(os.getpid() + 10000)
        process.__truediv__.return_value.read_bytes.return_value = b"/usr/sbin/warnquota\0-ug\0"
        with (
            patch.object(self.native, "Path") as paths,
            patch.object(self.native, "Event") as event,
            patch.object(self.native, "monotonic", return_value=0),
        ):
            paths.return_value.iterdir.side_effect = [[process], []]
            self.native._emitters_idle()
            self.assertEqual(paths.return_value.iterdir.call_count, 2)
            event.return_value.wait.assert_called_once_with(0.2)
        with (
            patch.object(self.native, "Path") as paths,
            patch.object(self.native, "Event"),
            patch.object(self.native, "monotonic", side_effect=[0, 16]),
            self.assertRaisesRegex(ValueError, "emitter"),
        ):
            paths.return_value.iterdir.return_value = [process]
            self.native._emitters_idle()

    def _backup_inventory(self, email, *, apply=False):
        program = r"""
require $ARGV[0];
package virtual_server;
our %config=(domain_template=>'none',subdomain_template=>'none',user_template=>'none',update_template=>'none');
our $backup={id=>1,email_doms=>0,email=>$ARGV[1],email_err=>1,enabled=>1,dest=>'/owned-backup.tar.gz'};
our $writes=0;
no warnings 'redefine';
*praho_operator_policy = sub { return ['operator@example.test']; };
sub list_templates { return (); }
sub list_domains { return (); }
sub list_scheduled_backups { return $backup; }
sub save_scheduled_backup { $writes++; }
sub save_module_config_keys { }
sub setup_scriptwarn_job { }
sub foreign_require { }
sub find_cron_script { return 0; }
package status;
sub list_services { return (); }
package virtual_server;
praho_apply_notification_policy(['operator@example.test']) if $ARGV[2];
my $inventory=praho_notification_inventory();
print JSON::PP->new->canonical->encode($ARGV[2] ? {inventory=>$inventory,backup=>$backup,writes=>$writes} : $inventory);
"""
        result = subprocess.run(  # noqa: S603 -- Fixed native policy; only native inventory/config I/O is doubled.
            [
                "/usr/bin/perl",
                "-e",
                program,
                str(self.files / "praho-notification-policy.pl"),
                email,
                "1" if apply else "0",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)

    def test_explicit_scheduled_backup_customer_recipient_is_not_operator_authority(self):
        result = self._backup_inventory("customer@example.test")
        self.assertFalse(result["evidence"]["emitters"]["backup_owners"])

    def test_explicit_approved_operator_backup_recipient_remains_supported(self):
        result = self._backup_inventory("operator@example.test")
        self.assertTrue(result["evidence"]["emitters"]["backup_owners"])

    def test_handover_persists_only_approved_backup_recipients_without_changing_the_job(self):
        for email, expected, writes in (
            ("customer@example.test", "", 1),
            ("customer@example.test,operator@example.test", "operator@example.test", 1),
            ("operator@example.test", "operator@example.test", 0),
        ):
            with self.subTest(email=email):
                result = self._backup_inventory(email, apply=True)
                self.assertEqual(
                    result["backup"],
                    {
                        "id": 1,
                        "email_doms": 0,
                        "email": expected,
                        "email_err": 1,
                        "enabled": 1,
                        "dest": "/owned-backup.tar.gz",
                    },
                )
                self.assertEqual(result["writes"], writes)
                self.assertTrue(result["inventory"]["evidence"]["emitters"]["backup_owners"])

    def _acme_delivery(self, marker, *, mode=0o600, legacy_patch=False, native_uid=0):
        status = (self.fixtures / "virtualmin_existing_monitor_8_3.pl").read_text()
        source = (self.fixtures / "virtualmin_acme_notification_8_3.pl").read_text()
        if legacy_patch:
            source = source.replace(
                self.native.ACME_OWNER_BRANCH, self.native.ACME_OWNER_BRANCH + self.native.ACME_MASTER_BRANCH
            )
        _, corrected = self.native.notification_source_patches(status, source)
        self.assertEqual(self.native.notification_source_patches(status, corrected)[1], corrected)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            marker_path = root / "notification-owner"
            if marker is not None:
                marker_path.write_text(marker)
                marker_path.chmod(mode)
            adapter = root / "policy.pl"
            adapter.write_text(
                (self.files / "praho-notification-policy.pl")
                .read_text()
                .replace("/var/lib/praho/hosting/notification-owner", str(marker_path))
            )
            corrected = corrected.replace("/usr/local/lib/praho/praho-notification-policy.pl", str(adapter))
            program = (
                r"""use JSON::PP;
# Native ownership is the external OS boundary: temporary fixture bytes/inodes
# are real, with only the host's non-root uid mapped to the production root uid.
BEGIN {
 *CORE::GLOBAL::lstat = sub { my @s=CORE::lstat($_[0]);$s[4]=NATIVE_UID if @s;return @s; };
 *CORE::GLOBAL::stat = sub { my @s=CORE::stat($_[0]);$s[4]=NATIVE_UID if @s;return @s; };
}
package virtual_server;
our @attempts; our %gconfig=(webmin_email_to=>'operator@example.test');
sub send_notify_email {
 my ($from,$domains)=@_;push @attempts,map {$_->{'emailto'}} @$domains;
 push @attempts,$_[11] if $_[11];
}
sub unlock_domain { }
sub emit { my ($d)=@_;my $ok=1;
"""
                + corrected
                + r"""
emit(JSON::PP->new->decode($ARGV[0]));
END { print JSON::PP->new->canonical->encode(\@attempts); }
"""
            )
            program = program.replace("NATIVE_UID", str(native_uid))
            result = subprocess.run(  # noqa: S603 -- Execute the actual patched native branch with captured mail transport.
                [
                    "/usr/bin/perl",
                    "-e",
                    program,
                    json.dumps(
                        {"emailto": "customer@example.test", "letsencrypt_email": 0, "letsencrypt_email_master": 1}
                    ),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        return result, json.loads(result.stdout)

    def test_restored_owner_acme_flags_cannot_bypass_platform_ownership(self):
        result, recipients = self._acme_delivery("platform\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recipients, ["operator@example.test"])

    def test_legacy_patched_acme_source_upgrades_without_reenabling_owner_mail(self):
        result, recipients = self._acme_delivery("platform\n", legacy_patch=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recipients, ["operator@example.test"])

    def test_unhanded_over_native_owner_and_master_mail_are_preserved(self):
        result, recipients = self._acme_delivery(None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recipients, ["customer@example.test", "operator@example.test"])

    def test_unknown_or_unreadable_owner_marker_refuses_before_customer_send(self):
        for marker, mode in (("unexpected\n", 0o600), ("platform\n", 0o000)):
            with self.subTest(marker=marker, mode=mode):
                result, recipients = self._acme_delivery(marker, mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(recipients, [])
        result, recipients = self._acme_delivery("platform\n", native_uid=os.getuid() or 1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(recipients, [])

    def test_a_second_unguarded_acme_branch_cannot_hide_behind_an_existing_patch(self):
        status = (self.fixtures / "virtualmin_existing_monitor_8_3.pl").read_text()
        ssl = (self.fixtures / "virtualmin_acme_notification_8_3.pl").read_text()
        _, corrected = self.native.notification_source_patches(status, ssl)
        with self.assertRaises(ValueError):
            self.native.notification_source_patches(status, corrected + self.native.ACME_OWNER_BRANCH)
