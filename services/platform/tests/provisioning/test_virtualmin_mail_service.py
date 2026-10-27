"""Bounded native mail receipts bind node/account identity and never project credentials."""

from __future__ import annotations

import base64
import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase

from apps.common.types import Err, Ok, Retriability, retriability_of
from apps.provisioning import virtualmin_mail_service as mail


class MailNativeReceiptTests(SimpleTestCase):
    def setUp(self):
        self.server = SimpleNamespace(pk=uuid4(), hostname="vm-a.example", node_deployment=object())
        self.account = SimpleNamespace(
            domain="customer.example",
            virtualmin_username="customer",
            server=self.server,
            account_hostname=SimpleNamespace(fqdn="h1234567.accounts.example", retired_at=None),
        )
        self.runner = Mock()
        self.enterContext(patch.object(mail, "_mail_zones", return_value=("accounts.example",), create=True))
        self.enterContext(patch.object(mail, "_runner", return_value=self.runner))
        self.runner.run_playbook.side_effect = self.answer
        self.payload = self.domain_payload()

    def domain_payload(self, **changes):
        return {
            "node_hostname": self.server.hostname,
            "profile": "debian12-dovecot23",
            "domain": self.account.domain,
            "domain_id": "42",
            "owner": self.account.virtualmin_username,
            "owner_uid": 1001,
            "mail_enabled": False,
            "users": [],
            "aliases": [],
            "dkim": None,
            "certificates": [],
            "ready": False,
            **changes,
        }

    def answer(self, deployment, playbook, variables, **kwargs):
        self.variables = variables
        payload = {
            "version": 1,
            "identity": variables["mail_operation_id"],
            "action": variables["mail_action"],
            "node_hostname": self.server.hostname,
            "payload": self.payload,
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        return Ok(SimpleNamespace(success=True, stdout="MAIL_RESULT=" + encoded))

    def test_mail_off_domain_can_be_observed_before_enrollment(self):
        result = mail.inspect_mail_domain(self.account).unwrap()
        self.assertEqual(result.domain_id, "42")
        self.assertFalse(result.mail_enabled)
        self.assertFalse(result.ready)
        self.assertEqual(result.owner_uid, 1001)

    def test_native_call_binds_exact_node_domain_owner_stable_name_and_operation(self):
        mail.inspect_mail_domain(self.account).unwrap()
        call = self.runner.run_playbook.call_args
        self.assertIs(call.args[0], self.server.node_deployment)
        self.assertEqual(call.args[1], "virtualmin_mail.yml")
        self.assertEqual(self.variables["mail_action"], "inspect_domain")
        self.assertEqual(self.variables["mail_domain"], self.account.domain)
        self.assertEqual(self.variables["mail_expected_owner"], "customer")
        self.assertEqual(self.variables["mail_account_hostname"], self.account.account_hostname.fqdn)
        self.assertEqual(self.variables["mail_expected_node_hostname"], self.server.hostname)
        self.assertGreater(call.kwargs["timeout_seconds"], 0)

    def test_mail_off_domain_does_not_require_an_account_name_to_observe_identity(self):
        self.account.account_hostname = None
        result = mail.inspect_mail_domain(self.account).unwrap()
        self.assertFalse(result.ready)
        self.assertEqual(self.variables["mail_account_hostname"], "")

    def test_foreign_native_domain_owner_node_and_unsafe_owner_uid_are_refused(self):
        for changes in (
            {"domain": "other.example"},
            {"owner": "other"},
            {"owner_uid": 0},
            {"node_hostname": "other-node.example"},
            {"domain_id": "../42"},
            {"owner_uid": True},
        ):
            with self.subTest(changes=changes):
                self.payload = self.domain_payload(**changes)
                self.assertTrue(mail.inspect_mail_domain(self.account).is_err())

    def test_unsupported_native_profile_is_explicitly_refused(self):
        self.payload["profile"] = "debian13-dovecot24"
        self.assertEqual(mail.inspect_mail_domain(self.account).unwrap_err(), "mail_profile_unsupported")

    def test_node_observation_retains_the_verified_ubuntu_profile_identity(self):
        self.payload = {
            "node_hostname": self.server.hostname,
            "profile": "ubuntu2604-dovecot24",
            "configured": False,
            "default_mail_off": True,
            "public_ports": [],
        }
        result = mail.inspect_mail_node(self.server).unwrap()
        self.assertEqual(result.profile, "ubuntu2604-dovecot24")
        self.assertFalse(result.configured)
        self.assertTrue(result.default_mail_off)

    def test_native_profile_refusal_receipt_is_not_an_ambiguous_retry_permission(self):
        self.payload = {"error": "mail_profile_unsupported", "stage": "preflight"}
        result = mail.setup_mail_capability(self.server)
        self.assertEqual(result.unwrap_err(), "mail_profile_unsupported")
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)

    def test_preflight_certificate_refusal_is_retryable_without_claiming_late_failure_safe(self):
        self.payload = {"error": "mail_node_certificate_unproven", "stage": "node_certificate"}
        result = mail.setup_mail_capability(self.server)
        self.assertEqual(result.unwrap_err(), "mail_node_certificate_unproven")
        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)
        self.payload["stage"] = "service_start"
        self.assertEqual(retriability_of(mail.setup_mail_capability(self.server)), Retriability.UNKNOWN)

    def test_unknown_fields_never_become_public_native_projection(self):
        self.payload.update(password="private-password", private_key_path="/root/key", provider_token="provider-secret")
        value = asdict(mail.inspect_mail_domain(self.account).unwrap())
        self.assertNotIn("private-password", str(value))
        self.assertNotIn("/root/key", str(value))
        self.assertNotIn("provider-secret", str(value))

    def test_public_dkim_requires_an_owned_record_and_a_real_strong_rsa_key(self):
        public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        encoded = base64.b64encode(
            public.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()
        record = {
            "selector": "praho202610",
            "record_name": "praho202610._domainkey.customer.example",
            "record_value": "v=DKIM1; k=rsa; p=" + encoded,
        }
        self.payload["dkim"] = record
        self.assertEqual(mail.inspect_mail_domain(self.account).unwrap().dkim.record_value, record["record_value"])
        for changes in (
            {"record_name": "praho202610._domainkey.foreign.example"},
            {"record_value": "-----BEGIN PRIVATE KEY-----"},
            {"record_value": "v=DKIM1; k=rsa; p=broken"},
        ):
            with self.subTest(changes=changes):
                self.payload["dkim"] = {**record, **changes}
                self.assertTrue(mail.inspect_mail_domain(self.account).is_err())

    def test_native_users_are_bounded_safe_and_cannot_claim_another_owner_or_root_uid(self):
        user = {"login": "reader.customer", "email": "reader@customer.example", "uid": 1002, "enabled": True}
        self.payload["users"] = [user]
        result = mail.inspect_mail_domain(self.account).unwrap()
        self.assertEqual(result.users[0].login, "reader.customer")
        for changes in ({"uid": 0}, {"email": "reader@foreign.example"}, {"login": "../reader"}, {"enabled": 1}):
            with self.subTest(changes=changes):
                self.payload["users"] = [{**user, **changes}]
                self.assertTrue(mail.inspect_mail_domain(self.account).is_err())
        self.payload["users"] = [user] * (mail.MAX_MAIL_USERS + 1)
        self.assertTrue(mail.inspect_mail_domain(self.account).is_err())

    def test_duplicate_uid_or_login_does_not_create_two_claimed_mailbox_identities(self):
        self.payload["users"] = [
            {"login": "one.customer", "email": "one@customer.example", "uid": 1002, "enabled": True},
            {"login": "two.customer", "email": "two@customer.example", "uid": 1002, "enabled": True},
        ]
        self.assertTrue(mail.inspect_mail_domain(self.account).is_err())

    def test_aliases_preserve_catchall_and_external_addresses_but_never_commands_or_paths(self):
        self.payload["aliases"] = [{"address": "@customer.example", "targets": ["outside@external.example"]}]
        self.assertEqual(mail.inspect_mail_domain(self.account).unwrap().aliases[0].address, "@customer.example")
        for target in ("|/usr/bin/procmail", "/home/customer/private", "outside@external.example\nsecret"):
            with self.subTest(target=target):
                self.payload["aliases"][0]["targets"] = [target]
                self.assertTrue(mail.inspect_mail_domain(self.account).is_err())

    def test_node_only_certificate_cannot_establish_account_name_readiness(self):
        self.payload.update(
            mail_enabled=True,
            ready=True,
            users=[
                {"login": "reader.customer", "email": "reader@customer.example", "uid": 1002, "enabled": True},
            ],
        )
        self.payload["certificates"] = [
            {
                "service": "imap",
                "hostname": self.server.hostname,
                "sha256": "a" * 64,
                "not_after": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            }
        ]
        result = mail.inspect_mail_domain(self.account)
        self.assertTrue(result.is_err() or not result.unwrap().ready)

    def test_mail_off_or_incomplete_tls_proof_cannot_be_reported_ready(self):
        self.payload["ready"] = True
        self.assertFalse(mail.inspect_mail_domain(self.account).unwrap().ready)
        self.payload["mail_enabled"] = True
        self.assertFalse(mail.inspect_mail_domain(self.account).unwrap().ready)

    def test_all_actual_account_name_tls_services_can_establish_native_readiness(self):
        self.payload.update(
            mail_enabled=True,
            ready=True,
            users=[
                {"login": "reader.customer", "email": "reader@customer.example", "uid": 1002, "enabled": True},
            ],
        )
        self.payload["certificates"] = [
            {
                "service": service,
                "hostname": self.account.account_hostname.fqdn,
                "sha256": "a" * 64,
                "not_after": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            }
            for service in ("imap", "pop3", "submission", "smtp")
        ]
        self.assertTrue(mail.inspect_mail_domain(self.account).unwrap().ready)
        self.payload["certificates"][0]["not_after"] = datetime.now(UTC).isoformat()
        self.assertFalse(mail.inspect_mail_domain(self.account).unwrap().ready)

    def test_missing_managed_deployment_refuses_without_any_native_command(self):
        self.server.node_deployment = None
        self.assertTrue(mail.inspect_mail_domain(self.account).is_err())
        self.runner.run_playbook.assert_not_called()

    def test_raw_runner_errors_and_stderr_are_never_returned_as_public_messages(self):
        self.runner.run_playbook.side_effect = None
        self.runner.run_playbook.return_value = Err("password=secret node=10.0.0.8 private-key")
        result = mail.inspect_mail_domain(self.account)
        self.assertTrue(result.is_err())
        self.assertNotIn("secret", result.unwrap_err())
        self.assertNotIn("10.0.0.8", result.unwrap_err())

    def test_foreign_operation_or_malformed_base64_cannot_replay_a_native_receipt(self):
        original = self.answer

        def replay(*args, **kwargs):
            result = original(*args, **kwargs).unwrap()
            payload = json.loads(base64.b64decode(result.stdout.split("=", 1)[1]))
            payload["identity"] = str(uuid4())
            result.stdout = "MAIL_RESULT=" + base64.b64encode(json.dumps(payload).encode()).decode()
            return Ok(result)

        self.runner.run_playbook.side_effect = replay
        self.assertTrue(mail.inspect_mail_domain(self.account).is_err())
        self.runner.run_playbook.side_effect = None
        self.runner.run_playbook.return_value = Ok(SimpleNamespace(success=True, stdout="MAIL_RESULT=%%%"))
        self.assertTrue(mail.inspect_mail_domain(self.account).is_err())

    def test_node_capability_is_separate_from_domain_hosted_mode(self):
        self.payload = {
            "node_hostname": self.server.hostname,
            "profile": "debian12-dovecot23",
            "configured": True,
            "default_mail_off": True,
            "public_ports": [25, 465, 993, 995],
        }
        observed = mail.setup_mail_capability(self.server).unwrap()
        self.assertTrue(observed.configured)
        self.assertTrue(observed.default_mail_off)
        self.assertEqual(self.variables["mail_action"], "setup")
        self.payload["default_mail_off"] = False
        self.assertTrue(mail.setup_mail_capability(self.server).is_err())
        self.payload["default_mail_off"] = True
        self.payload["public_ports"].append(143)
        self.assertTrue(mail.inspect_mail_node(self.server).is_err())

    def test_read_only_node_observation_can_report_not_yet_installed(self):
        self.payload = {
            "node_hostname": self.server.hostname,
            "profile": "debian12-dovecot23",
            "configured": False,
            "default_mail_off": True,
            "public_ports": [],
        }
        self.assertFalse(mail.inspect_mail_node(self.server).unwrap().configured)
        self.assertEqual(self.variables["mail_action"], "inspect_node")

    def test_submitter_refresh_has_no_caller_supplied_authority_and_returns_only_fixed_receipt(self):
        self.payload = {
            "node_hostname": self.server.hostname,
            "profile": mail.MAIL_PROFILE,
            "configured": True,
            "default_mail_off": True,
            "maps_sha256": "a" * 64,
            "usernames": ["private-user"],
            "password": "private-password",
        }
        result = mail.reconcile_mail_submitters(self.server).unwrap()
        self.assertEqual(result.maps_sha256, "a" * 64)
        self.assertEqual(self.variables["mail_action"], "reconcile_submitters")
        self.assertEqual(json.loads(self.variables["mail_reserved_account_zones"]), ["accounts.example"])
        self.assertNotIn("private-user", str(asdict(result)))
        self.assertNotIn("password", str(asdict(result)))

    def test_unconfigured_submitter_refresh_does_not_claim_authority(self):
        self.payload = {
            "node_hostname": self.server.hostname,
            "profile": mail.MAIL_PROFILE,
            "configured": False,
            "default_mail_off": True,
            "maps_sha256": "",
        }
        self.assertFalse(mail.reconcile_mail_submitters(self.server).unwrap().configured)
        self.payload["maps_sha256"] = "a" * 64
        self.assertTrue(mail.reconcile_mail_submitters(self.server).is_err())

    def test_reserved_zone_overflow_refuses_before_dispatch_instead_of_truncating(self):
        with patch.object(mail, "_mail_zones", side_effect=ValueError("overflow"), create=True):
            self.assertEqual(mail.reconcile_mail_submitters(self.server).unwrap_err(), "mail_reserved_zones_unproven")
        self.runner.run_playbook.assert_not_called()

    def test_certificate_reconcile_is_typed_and_bound_to_the_durable_operation(self):
        operation_id = uuid4()
        self.payload = {
            "node_hostname": self.server.hostname,
            "profile": mail.MAIL_PROFILE,
            "configured": True,
            "default_mail_off": True,
            "public_ports": [25, 465, 993, 995],
            "outcome": "replaced",
            "certificate_sha256": "a" * 64,
            "not_after": (datetime.now(UTC) + timedelta(days=20)).isoformat(),
            "pending_code": "",
            "private_key": "secret fixture",
        }
        observed = mail.reconcile_mail_node_certificate(self.server, operation_id=operation_id).unwrap()
        self.assertEqual(observed.outcome, "replaced")
        self.assertEqual(observed.certificate_sha256, "a" * 64)
        self.assertEqual(self.variables["mail_operation_id"], str(operation_id))
        self.assertEqual(self.variables["mail_action"], "reconcile_node_certificate")
        self.assertNotIn("secret fixture", str(asdict(observed)))
        self.assertGreater(self.runner.run_playbook.call_args.kwargs["timeout_seconds"], 120)

    def test_certificate_reconcile_explicit_falsy_identity_refuses_before_runner_construction(self):
        for identity in (False, 0, ""):
            with self.subTest(identity=identity), patch.object(mail, "_runner") as runner:
                result = mail.reconcile_mail_node_certificate(self.server, operation_id=identity)
                self.assertTrue(result.is_err())
                runner.assert_not_called()
        self.runner.run_playbook.assert_not_called()

    def test_certificate_reconcile_refuses_false_readiness_and_unknown_pending_reasons(self):
        base = {
            "node_hostname": self.server.hostname,
            "profile": mail.MAIL_PROFILE,
            "configured": True,
            "default_mail_off": True,
            "public_ports": [25, 465, 993, 995],
            "outcome": "retained_previous",
            "certificate_sha256": "a" * 64,
            "not_after": (datetime.now(UTC) + timedelta(days=20)).isoformat(),
            "pending_code": "mail_node_certificate_unproven",
        }
        self.payload = dict(base)
        self.assertEqual(mail.reconcile_mail_node_certificate(self.server).unwrap().outcome, "retained_previous")
        for changes in (
            {"configured": False},
            {"pending_code": "raw provider detail"},
            {"certificate_sha256": "not a fingerprint"},
            {"not_after": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()},
            {"outcome": "replaced"},
            {"outcome": "unknown"},
        ):
            with self.subTest(changes=changes):
                self.payload = {**base, **changes}
                self.assertTrue(mail.reconcile_mail_node_certificate(self.server).is_err())
