"""Native mail admission refuses uncertain state before changing the node."""

from __future__ import annotations

import configparser
import fcntl
import hashlib
import importlib.util
import json
import os
import ssl
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.test import SimpleTestCase

HELPER = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-mail.py"


class NativeMailNodeTests(SimpleTestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        spec = importlib.util.spec_from_file_location("mail_node", HELPER)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.commands = []
        self.queue = "0"
        self.version = "2.3.19.1"
        self.payload = {"mail_default_off": True, "mail_backend_selected": True, "mail_available": True, "domains": []}
        self.write("etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.write("usr/share/webmin/virtual-server/module.info", "version=8.3.0\n")
        self.write("usr/sbin/exim4", "fixture")
        self.write("etc/exim4/exim4.conf.template", "stock exim template\n")
        self.exim_package_digest = hashlib.md5(b"stock exim template\n", usedforsecurity=False).hexdigest()
        self.write("usr/sbin/iptables", "fixture")
        self.write("usr/sbin/ip6tables", "fixture")
        self.write(
            "etc/webmin/virtual-server/config", "dns_provider=external\ncloud_token=preserved-secret\nmail_system=99\n"
        )
        self.node = self.module.MailNode(self.root, execute=self.execute, probe=lambda hostname: [])
        self.enterContext(
            patch.dict(
                os.environ,
                {"PRAHO_MAIL_RESERVED_ZONES": '["accounts.example"]', "PRAHO_MAIL_ACCOUNT_ZONE": "accounts.example"},
            )
        )

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def execute(self, argv, **kwargs):
        self.commands.append(argv)
        if argv[:1] == ["dpkg-query"]:
            return " /etc/exim4/exim4.conf.template " + self.exim_package_digest + "\n"
        if argv[:1] == ["perl"]:
            return json.dumps(self.payload)
        return {
            ("hostname", "-f"): "node.example\n",
            ("exim4", "-bpc"): self.queue,
            ("dovecot", "--version"): self.version,
            ("postconf", "-h", "mail_version"): "3.7.11",
            ("apt-cache", "policy", "dovecot-core"): "  Candidate: 1:2.3.19.1+dfsg1\n",
            ("apt-cache", "policy", "postfix"): "  Candidate: 3.7.11\n",
        }.get(tuple(argv), "")

    def assert_no_node_mutation(self):
        self.assertFalse((self.root / "var/lib/praho/mail").exists())
        self.assertFalse(
            any(command[0] in {"apt-get", "postfix", "systemctl", "iptables", "ip6tables"} for command in self.commands)
        )
        self.assertEqual(
            (self.root / "etc/webmin/virtual-server/config").read_text(),
            "dns_provider=external\ncloud_token=preserved-secret\nmail_system=99\n",
        )

    def test_unsupported_distribution_and_dovecot_version_refuse_before_mutation(self):
        self.write("etc/os-release", 'ID=debian\nVERSION_ID="13"\n')
        with self.assertRaisesRegex(self.module.MailError, "mail_profile_unsupported"):
            self.node.preflight_setup("node.example")
        self.assert_no_node_mutation()
        self.write("etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.write("usr/sbin/dovecot", "fixture")
        self.version = "2.4.1"
        with self.assertRaisesRegex(self.module.MailError, "mail_profile_unsupported"):
            self.node.preflight_setup("node.example")
        self.assert_no_node_mutation()

    def test_ubuntu26_observation_selects_its_own_profile_without_enabling_mail(self):
        self.write("etc/os-release", 'ID=ubuntu\nVERSION_ID="26.04"\n')
        result = self.node.inspect_node("node.example")
        self.assertEqual(result["profile"], "ubuntu2604-dovecot24")
        self.assertFalse(result["configured"])
        self.assertTrue(result["default_mail_off"])
        self.assertEqual(result["public_ports"], [])
        self.assert_no_node_mutation()

    def test_dovecot_versions_cannot_cross_their_distribution_profiles(self):
        self.write("usr/sbin/dovecot", "fixture")
        for distribution, release, version in (
            ("ubuntu", "26.04", "2.3.19.1"),
            ("ubuntu", "24.04", "2.4.2"),
            ("debian", "12", "2.4.2"),
        ):
            with self.subTest(distribution=distribution, release=release, version=version):
                self.write("etc/os-release", f'ID={distribution}\nVERSION_ID="{release}"\n')
                self.version = version
                with self.assertRaisesRegex(self.module.MailError, "mail_profile_unsupported"):
                    self.node.inspect_node("node.example")
                self.assert_no_node_mutation()

    def test_package_candidates_follow_the_selected_distribution_profile(self):
        self.write("etc/os-release", 'ID=ubuntu\nVERSION_ID="26.04"\n')
        candidates = {"postfix": "3.10.6-4ubuntu2.2", "dovecot-core": "1:2.4.2+dfsg1-3ubuntu2.1"}

        def execute(argv, **kwargs):
            if argv[:2] == ["apt-cache", "policy"]:
                return "  Candidate: " + candidates[argv[2]] + "\n"
            return self.execute(argv, **kwargs)

        self.node.execute = execute
        driver = self.node.setup_driver()
        driver.candidates()
        candidates["dovecot-core"] = "1:2.3.19.1"
        with self.assertRaisesRegex(self.module.MailError, "mail_profile_unsupported"):
            driver.candidates()
        self.assert_no_node_mutation()

    def test_ubuntu_authentication_readiness_checks_named_databases_and_their_results(self):
        self.write("etc/os-release", 'ID=ubuntu\nVERSION_ID="26.04"\n')
        configuration = """passdb praho-deny {
  deny = yes
  driver = passwd-file
  result_internalfail = return-fail
  passwd_file_path = /etc/dovecot/praho-deny
}
passdb praho-proxy {
  auth_username_format = %{user}
  driver = passwd-file
  result_failure = return-fail
  result_internalfail = return-fail
  result_success = return-ok
  passwd_file_path = /etc/dovecot/praho-proxy-%{protocol}
}
"""
        values = {
            "ssl": "required",
            "ssl_min_protocol": "TLSv1.2",
            "auth_allow_cleartext": "no",
            "login_trusted_networks": "",
            "auth_verbose_passwords": "no",
            "auth_cache_size": "0",
        }

        def execute(argv, **kwargs):
            if argv == ["doveconf", "-n"]:
                return configuration
            if argv[:2] == ["doveconf", "-h"]:
                return values[argv[2]]
            return self.execute(argv, **kwargs)

        self.node.execute = execute
        driver = self.node.setup_driver()
        driver.dovecot_security()
        valid = configuration
        for before, after in (
            ("deny = yes", "deny = no"),
            ("driver = passwd-file", "driver = pam"),
            ("result_internalfail = return-fail", "result_internalfail = continue"),
            ("result_failure = return-fail", "result_failure = continue"),
            ("praho-proxy-%{protocol}", "praho-proxy-smtp"),
        ):
            with self.subTest(before=before, after=after):
                configuration = valid.replace(before, after)
                with self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"):
                    driver.dovecot_security()

    def test_node_hostname_mismatch_refuses_before_any_configuration_change(self):
        with self.assertRaisesRegex(self.module.MailError, "mail_node_identity_mismatch"):
            self.node.preflight_setup("another.example")
        self.assert_no_node_mutation()

    def test_nonempty_or_unreadable_exim_queue_is_not_replaced(self):
        for count in ("3", "", "unknown", "-1", "0\nwarning"):
            with self.subTest(count=count):
                self.queue = count
                with self.assertRaisesRegex(self.module.MailError, "mail_queue_uncertain"):
                    self.node.preflight_setup("node.example")
                self.assert_no_node_mutation()

    def test_existing_unmarked_postfix_or_mail_enabled_domain_is_not_adopted(self):
        self.write("usr/sbin/postfix", "fixture")
        with self.assertRaisesRegex(self.module.MailError, "mail_unmanaged_mta"):
            self.node.preflight_setup("node.example")
        self.assert_no_node_mutation()
        (self.root / "usr/sbin/postfix").unlink()
        self.payload["domains"] = [{"domain": "unmanaged.example", "mail_enabled": True}]
        with self.assertRaisesRegex(self.module.MailError, "mail_unmanaged_mta"):
            self.node.preflight_setup("node.example")
        self.assert_no_node_mutation()

    def test_exact_zero_exim_queue_is_eligible_without_touching_provider_configuration(self):
        result = self.node.preflight_setup("node.example")
        self.assertEqual(result["mta"], "exim4")
        self.assertTrue(result["mail_default_off"])
        self.assert_no_node_mutation()

    def test_native_projection_observes_mail_off_owner_without_exposing_root_fields(self):
        self.payload = {
            "domain": "customer.example",
            "domain_id": "42",
            "owner": "customer",
            "owner_uid": 1001,
            "mail_enabled": False,
            "users": [],
            "aliases": [],
            "dkim": None,
            "pass": "$6$private",
            "plainpass": "secret",
            "home": "/home/customer",
            "sslkey": "/root/key",
        }
        result = self.node.inspect_domain("node.example", "customer.example", "customer", "")
        self.assertFalse(result["ready"])
        self.assertEqual(result["owner_uid"], 1001)
        for secret in ("$6$private", "secret", "/home/customer", "/root/key"):
            self.assertNotIn(secret, json.dumps(result))

    def test_domain_owner_uid_and_foreign_identity_conflicts_are_refused(self):
        baseline = {
            "domain": "customer.example",
            "domain_id": "42",
            "owner": "customer",
            "owner_uid": 1001,
            "mail_enabled": False,
            "users": [],
            "aliases": [],
            "dkim": None,
        }
        for changed in ({"domain": "other.example"}, {"owner": "root"}, {"owner_uid": 0}, {"owner_uid": True}):
            with self.subTest(changed=changed):
                self.payload = {**baseline, **changed}
                with self.assertRaisesRegex(self.module.MailError, "mail_domain_identity_mismatch"):
                    self.node.inspect_domain("node.example", "customer.example", "customer", "")

    def test_oversized_native_inventory_is_refused_whole_without_truncating_users(self):
        self.payload = {
            "domain": "customer.example",
            "domain_id": "42",
            "owner": "customer",
            "owner_uid": 1001,
            "mail_enabled": True,
            "users": [{}] * 1001,
            "aliases": [],
            "dkim": None,
        }
        with self.assertRaises(self.module.MailError):
            self.node.inspect_domain("node.example", "customer.example", "customer", "")

    def test_explicit_mail_default_off_is_part_of_capability_even_before_install(self):
        result = self.node.inspect_node("node.example")
        self.assertFalse(result["configured"])
        self.assertTrue(result["default_mail_off"])
        self.assertEqual(result["public_ports"], [])

    def test_custom_procmail_recipe_is_refused_before_replacing_mail_delivery(self):
        self.write("etc/procmailrc", ":0\n| /usr/local/bin/operator-delivery\n")
        with self.assertRaisesRegex(self.module.MailError, "mail_unmanaged_mta"):
            self.node.preflight_setup("node.example")
        self.assert_no_node_mutation()

    def test_native_procmail_defaults_are_preserved_and_eligible(self):
        baseline = (
            "LOGFILE=/var/log/procmail.log\nTRAP=/etc/webmin/virtual-server/procmail-logger.pl\n"
            "ORGMAIL=/var/mail/$LOGNAME\nDEFAULT=/var/mail/$LOGNAME\nDROPPRIVS=yes\n"
        )
        self.write("etc/procmailrc", baseline)
        self.assertEqual(self.node.preflight_setup("node.example")["mta"], "exim4")
        self.assertEqual((self.root / "etc/procmailrc").read_text(), baseline)
        self.assert_no_node_mutation()

    def test_unowned_dovecot_authentication_is_not_replaced_even_without_postfix(self):
        self.write("usr/sbin/dovecot", "fixture")
        self.write("etc/dovecot/conf.d/auth-system.conf.ext", "passdb { driver = pam }\n")
        with self.assertRaisesRegex(self.module.MailError, "mail_unmanaged_mta"):
            self.node.preflight_setup("node.example")
        self.assert_no_node_mutation()

    def test_unknown_sendmail_backend_is_not_treated_as_no_mta(self):
        (self.root / "usr/sbin/exim4").unlink()
        self.write("usr/sbin/sendmail", "unmanaged binary")
        with self.assertRaisesRegex(self.module.MailError, "mail_unmanaged_mta"):
            self.node.preflight_setup("node.example")
        self.assert_no_node_mutation()

    def test_mail_enabled_and_certificates_alone_do_not_claim_managed_domain_readiness(self):
        self.payload = {
            "domain": "customer.example",
            "domain_id": "42",
            "owner": "customer",
            "owner_uid": 1001,
            "mail_enabled": True,
            "users": [{"login": "customer", "email": "a@customer.example", "uid": 1001, "enabled": True}],
            "aliases": [],
            "dkim": None,
        }
        self.node.probe = lambda name: [
            {"service": service, "hostname": name} for service in ("imap", "pop3", "submission", "smtp")
        ]
        result = self.node.inspect_domain("node.example", "customer.example", "customer", "client.example")
        self.assertFalse(result["ready"])

    def test_setup_requires_verified_node_certificate_before_package_or_firewall_mutation(self):
        with self.assertRaisesRegex(self.module.MailError, "mail_node_certificate_unproven"):
            self.node.setup("node.example")
        self.assert_no_node_mutation()

    def test_preflight_uses_the_runtime_tls_clients_strict_certificate_policy(self):
        self.write("etc/webmin/miniserv.conf", "keyfile=/etc/webmin/node.key\ncertfile=/etc/webmin/node.pem\n")
        self.write("etc/webmin/node.key", "fake key").chmod(0o600)
        self.write("etc/webmin/node.pem", "fake public chain").chmod(0o600)
        (self.root / "run").mkdir()
        driver = self.node.setup_driver()
        original_stat = Path.stat

        def root_stat(path, **kwargs):
            info = original_stat(path, **kwargs)
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode)

        def execute(argv, **kwargs):
            if argv[:2] == ["openssl", "verify"]:
                if "-x509_strict" in argv:
                    raise RuntimeError("fixture CA is rejected by strict certificate validation")
                return "OK"
            if "-enddate" in argv:
                return "notAfter=" + (datetime.now(UTC) + timedelta(days=20)).strftime("%b %d %H:%M:%S %Y GMT")
            return "fake public key" if "-pubout" in argv or "-pubkey" in argv else "fake key"

        driver.execute = execute
        context = SimpleNamespace(verify_flags=0)
        with (
            patch.object(Path, "stat", root_stat),
            patch.object(driver, "certificate_chain", return_value=b"fake public chain"),
            patch("ssl.create_default_context", return_value=context),
        ):
            self.assertEqual(driver.certificate("node.example"), (b"fake public chain", b"fake key"))
            context.verify_flags = ssl.VERIFY_X509_STRICT
            with self.assertRaisesRegex(self.module.MailError, "mail_node_certificate_unproven"):
                driver.certificate("node.example")

    def test_interrupted_setup_marker_never_authorizes_blind_replacement(self):
        self.write(
            "var/lib/praho/mail/node.json",
            json.dumps({"version": 1, "profile": "debian12-dovecot23", "node": "node.example", "status": "applying"}),
        )
        with self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"):
            self.node.setup("node.example")
        self.assertFalse(any(command[0] == "apt-get" for command in self.commands))

    def test_failed_or_interrupted_setup_persists_review_and_masks_services_before_propagating(self):
        self.write("etc/webmin/mailboxes/config", "mail_system=6\n")
        self.write("proc/self/stat", "123 (fixture) " + " ".join(["0"] * 19 + ["456"]))
        self.write("proc/sys/kernel/random/boot_id", "fixture-boot\n")
        for failure in (RuntimeError("package failure"), KeyboardInterrupt(), SystemExit(2)):
            with self.subTest(failure=type(failure).__name__):
                driver = self.node.setup_driver()
                with (
                    patch.object(driver, "certificate", return_value=(b"public chain", b"private fixture")),
                    patch.object(driver, "install_packages", side_effect=failure),
                    self.assertRaises(type(failure)) as raised,
                ):
                    driver.run("node.example")
                self.assertIs(raised.exception, failure)
                marker = self.root / "var/lib/praho/mail/node.json"
                self.assertEqual(json.loads(marker.read_text())["status"], "review_required")
                self.assertIn(["systemctl", "mask", "--now", "postfix.service", "dovecot.service"], self.commands)
                self.assertNotIn(["systemctl", "restart", "dovecot", "postfix"], self.commands)
                marker.unlink()
                marker.parent.rmdir()
                self.commands.clear()

    def test_package_policy_restores_existing_operator_bytes_and_mode_on_failure(self):
        original = b"#!/bin/sh\n# operator policy\nexit 0\n"
        file = self.write("usr/sbin/policy-rc.d", original.decode())
        file.chmod(0o751)
        driver = self.node.setup_driver()
        with self.assertRaisesRegex(RuntimeError, "fixture failure"), driver.package_policy():
            self.assertEqual(file.read_text(), "#!/bin/sh\nexit 101\n")
            raise RuntimeError("fixture failure")
        self.assertEqual(file.read_bytes(), original)
        self.assertEqual(file.stat().st_mode & 0o777, 0o751)

    def test_startup_preflight_has_its_own_privilege_scope_without_weakening_the_daemon(self):
        self.node.setup_driver().install_boot_guard()
        for unit in ("postfix.service", "postfix@.service", "dovecot.service"):
            with self.subTest(unit=unit):
                file = self.root / ("etc/systemd/system/" + unit + ".d/praho-mail.conf")
                configuration = configparser.ConfigParser()
                configuration.read_string(file.read_text())
                self.assertEqual(set(configuration.sections()), {"Service"})
                self.assertEqual(set(configuration["Service"]), {"execstartpre"})
                executable, script = configuration["Service"]["ExecStartPre"].split()
                self.assertEqual(executable, "+/usr/bin/python3")
                self.assertEqual(script, "/usr/lib/praho/mail/praho-mail-boot.py")

    def test_package_policy_does_not_overwrite_concurrent_operator_change(self):
        file = self.write("usr/sbin/policy-rc.d", "original\n")
        with (
            self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"),
            self.node.setup_driver().package_policy(),
        ):
            file.write_text("operator changed policy\n")
        self.assertEqual(file.read_text(), "operator changed policy\n")

    def test_capability_requires_post_tls_smtp_auth_to_remain_disabled(self):
        connection = type(
            "Connection",
            (),
            {
                "ehlo": lambda self: None,
                "starttls": lambda self, **kw: None,
                "has_extn": lambda self, name: name == "auth",
                "close": lambda self: None,
            },
        )()
        with (
            patch("smtplib.SMTP.__init__", return_value=None),
            patch("smtplib.SMTP.ehlo", connection.ehlo),
            patch("smtplib.SMTP.starttls", connection.starttls),
            patch("smtplib.SMTP.has_extn", connection.has_extn),
            patch("smtplib.SMTP.close", connection.close),
            patch("socket.create_connection", side_effect=OSError),
        ):
            self.assertEqual(self.module.tls_observations("node.example"), [])

    def test_configured_marker_cannot_hide_an_extra_native_pam_fallback(self):
        driver = self.node.setup_driver()
        self.write("etc/dovecot/praho-proxy-smtp", "")
        self.write("etc/postfix/praho-local-senders", "postfix *\nroot *\n")
        expected = driver.security.__func__.__globals__["POSTFIX"]
        commands = {
            **{("postconf", "-h", key): value for key, value in expected.items()},
            ("postconf", "-P", "smtp/inet/smtpd_sasl_auth_enable"): "smtp/inet/smtpd_sasl_auth_enable = no",
            ("postconf", "-M"): "smtp inet n - y - - smtpd\n127.0.0.1:1465 inet n - n - - smtpd\n",
            ("iptables-save", "-t", "filter"): "*filter\nCOMMIT\n",
            ("ip6tables-save", "-t", "filter"): "*filter\nCOMMIT\n",
            ("doveconf", "-n"): "passdb {\n  driver = pam\n}\n",
        }
        driver.execute = lambda argv: commands.get(tuple(argv), "")
        self.node.probe = lambda name: [{"service": service} for service in ("imap", "pop3", "submission", "smtp")]
        with (
            patch.object(driver, "marker", return_value={"status": "ready"}),
            patch.object(self.node, "public_ports", return_value=[25, 465, 993, 995]),
            self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"),
        ):
            driver.security("node.example")

    def test_mailbox_throttle_template_accepts_explicit_policy_without_changing_global_pam(self):
        driver = self.node.setup_driver()
        driver.templates = HELPER.parent.parent / "templates/mail"
        rendered = driver.render_pam(failures=10, window=300, unlock=300).decode()
        self.assertIn("deny=10 fail_interval=300 unlock_time=300", rendered)
        self.assertNotIn("@", rendered)
        self.assertFalse((self.root / "etc/pam.d/dovecot").exists())
        self.assert_no_node_mutation()

    def test_invalid_mailbox_throttle_values_cannot_enter_native_configuration(self):
        for values in ({"failures": True}, {"failures": 0}, {"failures": "10\nother"}, {"window": 0}, {"unlock": -1}):
            with self.subTest(values=values), self.assertRaises(self.module.MailError):
                self.node.setup_driver().render_pam(**{"failures": 5, "window": 300, "unlock": 300, **values})
        self.assert_no_node_mutation()

    def test_native_backend_selector_drift_invalidates_previously_configured_capability(self):
        driver = self.node.setup_driver()
        self.write("etc/dovecot/praho-proxy-smtp", "")
        self.write("etc/postfix/praho-local-senders", "postfix *\nroot *\n")
        expected = driver.security.__func__.__globals__["POSTFIX"]
        commands = {
            **{("postconf", "-h", key): value for key, value in expected.items()},
            ("postconf", "-P", "smtp/inet/smtpd_sasl_auth_enable"): "smtp/inet/smtpd_sasl_auth_enable = no",
            ("postconf", "-M"): "smtp inet n - y - - smtpd\n127.0.0.1:1465 inet n - n - - smtpd\n",
            ("iptables-save", "-t", "filter"): "*filter\nCOMMIT\n",
            ("ip6tables-save", "-t", "filter"): "*filter\nCOMMIT\n",
        }
        driver.execute = lambda argv: commands.get(tuple(argv), "")
        self.node.probe = lambda name: [{"service": service} for service in ("imap", "pop3", "submission", "smtp")]
        with (
            patch.object(driver, "marker", return_value={"status": "ready"}),
            patch.object(driver, "dovecot_security"),
            patch.object(self.node, "public_ports", return_value=[25, 465, 993, 995]),
        ):
            self.assertTrue(driver.security("node.example"))
            self.payload["mail_backend_selected"] = False
            with self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"):
                driver.security("node.example")
            self.payload["mail_backend_selected"] = True
            self.payload["mail_available"] = False
            with self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"):
                driver.security("node.example")
            self.payload["mail_available"] = True
            commands[("postconf", "-P", "smtp/inet/smtpd_sasl_auth_enable")] = "smtp/inet/smtpd_sasl_auth_enable = yes"
            with self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"):
                driver.security("node.example")

    def test_installation_fence_initially_blocks_local_plaintext_package_defaults_too(self):
        self.node.setup_driver().install_fence()
        self.assertFalse(any("RETURN" in command for command in self.commands))
        for program in ("iptables", "ip6tables"):
            self.assertIn([program, "-w", "5", "-I", "INPUT", "1", "-j", "PRAHO_MAIL_SETUP"], self.commands)

    def test_residual_exim_spool_cannot_be_hidden_by_a_zero_queue_count(self):
        self.write("var/spool/exim4/input/1abcde-000001-H", "accepted-message-envelope")
        with self.assertRaisesRegex(self.module.MailError, "mail_queue_uncertain"):
            self.node.preflight_setup("node.example")
        self.assertEqual((self.root / "var/spool/exim4/input/1abcde-000001-H").read_text(), "accepted-message-envelope")
        self.assert_no_node_mutation()

    def test_ready_retry_removes_only_its_remaining_ipv6_fence_after_partial_teardown(self):
        driver = self.node.setup_driver()
        commands = []
        clean = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
        fenced = (
            "*filter\n:INPUT ACCEPT [0:0]\n:PRAHO_MAIL_SETUP - [0:0]\n"
            "-A INPUT -j PRAHO_MAIL_SETUP\n-A PRAHO_MAIL_SETUP -i lo -j RETURN\n"
            "-A PRAHO_MAIL_SETUP -p tcp -m multiport --dports 25,110,143,465,587,993,995 -j REJECT --reject-with icmp6-port-unreachable\nCOMMIT\n"
        )

        def execute(argv):
            commands.append(argv)
            if argv == ["iptables-save", "-t", "filter"]:
                return clean
            if argv == ["ip6tables-save", "-t", "filter"]:
                return fenced
            if argv[0] == "iptables":
                raise self.module.MailError("already removed IPv4 fence")
            return ""

        driver.execute = execute
        driver.cleanup_fence()
        mutations = [argv for argv in commands if argv[0] in {"iptables", "ip6tables"}]
        self.assertEqual(
            mutations,
            [
                ["ip6tables", "-w", "5", "-D", "INPUT", "-j", "PRAHO_MAIL_SETUP"],
                ["ip6tables", "-w", "5", "-F", "PRAHO_MAIL_SETUP"],
                ["ip6tables", "-w", "5", "-X", "PRAHO_MAIL_SETUP"],
            ],
        )

    def test_owned_firewall_chain_drift_is_retained_instead_of_blindly_deleted(self):
        driver = self.node.setup_driver()
        commands = []

        def execute(argv):
            commands.append(argv)
            return "*filter\n:PRAHO_MAIL_SETUP - [0:0]\n-A PRAHO_MAIL_SETUP -s 192.0.2.1 -j ACCEPT\nCOMMIT\n"

        driver.execute = execute
        with self.assertRaisesRegex(self.module.MailError, "mail_setup_review_required"):
            driver.cleanup_fence()
        self.assertFalse(any(argv[0] in {"iptables", "ip6tables"} for argv in commands))

    def test_public_certificate_chain_preserves_intermediate_and_excludes_private_key(self):
        leaf = b"-----BEGIN CERTIFICATE-----\nTEVBRg==\n-----END CERTIFICATE-----\n"
        intermediate = b"-----BEGIN CERTIFICATE-----\nSU5URVJNRURJQVRF\n-----END CERTIFICATE-----\n"
        key = b"-----BEGIN PRIVATE KEY-----\nPRIVATE\n-----END PRIVATE KEY-----\n"
        cert = self.write("node.pem", (key + leaf + intermediate).decode())
        extra = self.write("extra.pem", intermediate.decode())
        result = self.node.setup_driver().certificate_chain(cert, extra)
        self.assertEqual(result, leaf + intermediate)
        self.assertNotIn(b"PRIVATE", result)

    def test_native_check_timestamp_is_volatile_but_provider_credentials_are_preserved(self):
        self.write("etc/webmin/mailboxes/config", "mail_system=6\noperator_option=preserved\n")
        driver = self.node.setup_driver()
        before = driver.provider_digest()
        configuration = self.root / "etc/webmin/virtual-server/config"
        configuration.write_text(configuration.read_text() + "last_check=1234567890\n")
        self.assertEqual(driver.provider_digest(), before)
        configuration.write_text(configuration.read_text().replace("preserved-secret", "unexpected-change"))
        self.assertNotEqual(driver.provider_digest(), before)

    def test_native_blank_line_normalization_preserves_policy_but_not_changed_values(self):
        mailbox = self.write("etc/webmin/mailboxes/config", "mail_system=6\n\noperator_option=preserved\n")
        configuration = self.root / "etc/webmin/virtual-server/config"
        configuration.write_text("\n" + configuration.read_text() + "\n  \n")
        driver = self.node.setup_driver()
        before = driver.provider_digest()
        for path in (configuration, mailbox):
            path.write_text("\n".join(line for line in path.read_text().splitlines() if line.strip()) + "\n")
        self.assertEqual(driver.provider_digest(), before)
        normalized = configuration.read_text()
        for changed in (
            normalized.replace("preserved-secret", "unexpected-change"),
            normalized + "unrecognized native configuration\n",
        ):
            with self.subTest(changed=changed):
                configuration.write_text(changed)
                self.assertNotEqual(driver.provider_digest(), before)
        configuration.write_text(normalized)
        mailbox.write_text(mailbox.read_text().replace("operator_option=preserved", "operator_option=changed"))
        self.assertNotEqual(driver.provider_digest(), before)

    def test_native_renewal_bookkeeping_does_not_hide_certificate_or_provider_policy_changes(self):
        self.write("etc/webmin/mailboxes/config", "mail_system=6\noperator_option=preserved\n")
        driver = self.node.setup_driver()
        configuration = self.root / "etc/webmin/virtual-server/config"
        original = configuration.read_text()
        before = driver.provider_digest()
        configuration.write_text(original + "last_letsencrypt_mass_renewal=1234567890\n")
        self.assertEqual(driver.provider_digest(), before)
        for policy in (
            "letsencrypt_renew=0\n",
            "last_letsencrypt_mass_renewal_policy=disabled\n",
            "dns_zone_id=another-zone\n",
        ):
            with self.subTest(policy=policy):
                configuration.write_text(original + policy)
                self.assertNotEqual(driver.provider_digest(), before)
        configuration.write_text(original)
        mailbox_configuration = self.root / "etc/webmin/mailboxes/config"
        mailbox_configuration.write_text(mailbox_configuration.read_text() + "last_letsencrypt_mass_renewal=1\n")
        self.assertNotEqual(driver.provider_digest(), before)

    def test_customer_owned_legacy_runtime_lock_does_not_block_the_private_node_lock(self):
        legacy = self.write("run/lock/praho-mail.lock", "customer-owned legacy lock")
        with legacy.open("a") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.module.operation_lock(self.root) as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(os.fstat(lock.fileno()).st_mode & 0o777, 0o600)
        self.assertEqual((self.root / "run/praho-mail").stat().st_mode & 0o777, 0o700)

    def test_private_operation_directory_never_follows_a_symlink_or_uses_public_permissions(self):
        target = self.write("operator-target", "untouched")
        (self.root / "run").mkdir(exist_ok=True)
        directory = self.root / "run/praho-mail"
        directory.symlink_to(target)
        with self.assertRaises(self.module.MailError):
            self.module.operation_lock(self.root)
        self.assertEqual(target.read_text(), "untouched")
        directory.unlink()
        directory.mkdir(mode=0o777)
        directory.chmod(0o777)
        with self.assertRaises(self.module.MailError):
            self.module.operation_lock(self.root)

    def test_reconcile_on_an_unconfigured_node_does_not_install_or_initialize_authority(self):
        result = self.node.reconcile_submitters("node.example", ["accounts.example"])
        self.assertFalse(result["configured"])
        self.assertEqual(result["maps_sha256"], "")
        self.assert_no_node_mutation()

    def test_reserved_policy_requires_current_zone_to_be_present_before_any_mutation(self):
        for current in ("", "foreign.example"):
            with (
                self.subTest(current=current),
                patch.dict(os.environ, {"PRAHO_MAIL_ACCOUNT_ZONE": current}),
                self.assertRaises(self.module.MailError),
            ):
                self.node.reserved_zones()
        self.assert_no_node_mutation()

    def test_empty_exim_queue_does_not_authorize_replacing_custom_outgoing_routing(self):
        for relative, content in (
            ("etc/exim4/passwd.client", "relay.example:operator:private-secret\n"),
            ("etc/exim4/hubbed_hosts", "customer.example: relay.example\n"),
            ("etc/exim4/exim4.conf", "primary_hostname = node.example\n"),
            ("etc/exim4/exim4.conf.localmacros", "DCsmarthost = relay.example\n"),
            (
                "etc/exim4/update-exim4.conf.conf",
                "dc_eximconfig_configtype='smarthost'\ndc_smarthost='relay.example'\n",
            ),
        ):
            with self.subTest(relative=relative):
                path = self.write(relative, content)
                with self.assertRaisesRegex(self.module.MailError, "mail_unmanaged_mta"):
                    self.node.preflight_setup("node.example")
                self.assertEqual(path.read_text(), content)
                path.unlink()
        self.assert_no_node_mutation()

    def test_stock_empty_exim_client_configuration_remains_eligible(self):
        self.write("etc/exim4/passwd.client", "# stock client credential example\n")
        self.write("etc/exim4/update-exim4.conf.conf", "dc_eximconfig_configtype='local'\ndc_smarthost=''\n")
        self.assertEqual(self.node.preflight_setup("node.example")["mta"], "exim4")
        self.assert_no_node_mutation()

    def test_modified_packaged_exim_template_is_not_treated_as_managed_by_empty_queue(self):
        self.write("etc/exim4/exim4.conf.template", "operator relay configuration\n")
        with self.assertRaisesRegex(self.module.MailError, "mail_unmanaged_mta"):
            self.node.preflight_setup("node.example")
        self.assert_no_node_mutation()
