"""Hosted mail requires fresh bound readiness; pending owner work cannot disappear on retry."""

from datetime import timedelta
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone
from django_fsm import TransitionNotAllowed

from apps.audit.models import AuditEvent
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_mail_models import (
    VirtualminMailConfiguration,
    VirtualminMailOperation,
    mail_generation,
)
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.users.models import User
from tests.provisioning.test_account_hostname_models import _account, _make_server


class MailModelFixture:
    def setUp(self):
        self.server = _make_server()
        self.server.ipv4_address = "203.0.113.20"
        self.server.save(update_fields=["ipv4_address"])
        self.account = _account(self.server, "mail-model.example.test")
        self.account.service.username = "mail-model"
        self.account.service.save(update_fields=["username"])
        self.name = AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="mail1234", zone="accounts.example.test"
        )

    def prepared(self):
        return VirtualminMailConfiguration.objects.create(
            account=self.account,
            consent_digest="a" * 64,
            verified_at=timezone.now(),
            readiness={
                "version": 1,
                "consent_digest": "a" * 64,
                "generation": mail_generation(self.account),
                "native_ready": True,
                "dns_ready": True,
                "domain_id": "123456",
                "owner": self.account.virtualmin_username,
                "client_hostname": self.name.fqdn,
            },
        )


class MailConfigurationTests(MailModelFixture, TestCase):
    def test_existing_and_new_accounts_have_no_implicit_enrollment(self):
        self.assertFalse(VirtualminMailConfiguration.objects.filter(account=self.account).exists())
        config = VirtualminMailConfiguration.objects.create(account=self.account)
        self.assertEqual(config.mode, "external")
        with self.assertRaises(TransitionNotAllowed):
            config.enable_hosted()
        self.assertIsNone(config.hosted_since)

    def test_verified_enrollment_uses_a_protected_mode_transition(self):
        config = self.prepared()
        with self.assertRaises(AttributeError):
            config.mode = "hosted"
        config.enable_hosted()
        config.save()
        config.refresh_from_db()
        self.assertEqual(config.mode, "hosted")
        self.assertIsNotNone(config.hosted_since)

    def test_missing_native_or_dns_proof_refuses_activation(self):
        for missing in ("native_ready", "dns_ready", "generation", "domain_id", "owner", "client_hostname"):
            with self.subTest(missing=missing):
                config = self.prepared()
                del config.readiness[missing]
                with self.assertRaises(TransitionNotAllowed):
                    config.enable_hosted()
                config.delete()

    def test_stale_or_future_readiness_cannot_enable_mail(self):
        config = self.prepared()
        for when in (timezone.now() - timedelta(hours=2), timezone.now() + timedelta(minutes=5)):
            with self.subTest(when=when):
                config.verified_at = when
                with self.assertRaises(TransitionNotAllowed):
                    config.enable_hosted()

    def test_current_database_server_assignment_invalidates_an_already_loaded_proof(self):
        config = self.prepared()
        other = _make_server()
        VirtualminAccount.objects.filter(pk=self.account.pk).update(server=other)
        with self.assertRaises(TransitionNotAllowed):
            config.enable_hosted()

    def test_changed_node_address_invalidates_an_already_loaded_proof(self):
        config = self.prepared()
        self.server.ipv4_address = "203.0.113.21"
        self.server.save(update_fields=["ipv4_address"])
        with self.assertRaises(TransitionNotAllowed):
            config.enable_hosted()

    def test_changed_consent_cannot_reuse_an_older_dns_readiness_proof(self):
        config = self.prepared()
        config.consent_digest = "b" * 64
        with self.assertRaises(TransitionNotAllowed):
            config.enable_hosted()

    def test_accepted_mail_must_be_accounted_for_before_returning_to_external_mode(self):
        config = self.prepared()
        config.enable_hosted()
        config.save()
        with self.assertRaises(TransitionNotAllowed):
            config.disable_hosted()

    def test_an_enrollment_cannot_be_rebound_to_a_different_account(self):
        config = self.prepared()
        other = _account(self.server, "foreign-mail.example.test")
        config.account = other
        with self.assertRaises(ValidationError):
            config.save()
        with self.assertRaises(ValidationError):
            VirtualminMailConfiguration.objects.filter(pk=config.pk).update(account=other)

    def test_retiring_the_stable_client_name_invalidates_a_readiness_receipt(self):
        config = self.prepared()
        self.name.retired_at = timezone.now()
        self.name.save(update_fields=["retired_at"])
        with self.assertRaises(TransitionNotAllowed):
            config.enable_hosted()

    def test_invalid_mode_is_rejected_by_the_database(self):
        with self.assertRaisesRegex(IntegrityError, "mail_valid_mode"), transaction.atomic():
            VirtualminMailConfiguration.objects.bulk_create(
                [VirtualminMailConfiguration(account=self.account, mode="available")]
            )

    def test_queryset_cannot_skip_the_verified_mode_transition(self):
        config = VirtualminMailConfiguration.objects.create(account=self.account)
        with self.assertRaises(ValidationError):
            VirtualminMailConfiguration.objects.filter(pk=config.pk).update(mode="hosted")

    def test_configuration_audit_records_only_the_mode_that_was_saved(self):
        config = self.prepared()
        events = AuditEvent.objects.filter(action="configuration_changed", object_id=str(config.pk))
        self.assertEqual(events.count(), 1)
        config.enable_hosted()
        with self.assertRaises(ValidationError):
            config.save(update_fields=["readiness"])
        self.assertEqual(events.count(), 1, "An unsaved mode must not create an activation audit")
        config.save(update_fields=["mode", "hosted_since", "updated_at"])
        self.assertEqual(events.count(), 2)
        self.assertEqual(events.latest("timestamp").new_values["mode"], "hosted")

    def test_retirement_proof_from_an_old_enrollment_cannot_disable_a_new_one(self):
        config = self.prepared()
        readiness = dict(config.readiness)
        config.enable_hosted()
        config.save()
        old_retirement = {
            "generation": mail_generation(self.account),
            "hosted_since": config.hosted_since.isoformat(),
            "enrollment_id": str(config.enrollment_id),
            "checked_at": timezone.now().isoformat(),
            "native_disabled": True,
            "accepted_queue_empty": True,
        }
        config.retirement = old_retirement
        config.disable_hosted()
        config.save(update_fields=["mode"])
        config.refresh_from_db()
        self.assertEqual(config.readiness, {})
        self.assertIsNone(config.verified_at)
        config.readiness = readiness
        config.verified_at = timezone.now()
        config.consent_digest = "a" * 64
        config.enable_hosted()
        config.save(update_fields=["mode"])
        config.refresh_from_db()
        self.assertEqual(config.retirement, {})
        config.retirement = old_retirement
        with self.assertRaises(TransitionNotAllowed):
            config.disable_hosted()


class MailOperationIdentityTests(MailModelFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.config = VirtualminMailConfiguration.objects.create(account=self.account)
        self.user = User.objects.create_user(email="mail-owner@example.test", password="Owner-test123!")

    def operation(self, **overrides):
        values = {
            "configuration": self.config,
            "requested_customer": self.account.service.customer,
            "requested_by": self.user,
            "submission_id": uuid4(),
            "intent": "enable",
            "target_generation": mail_generation(self.account),
            "consent_digest": "a" * 64,
            "confirmed_plan": {"version": 1, "records": []},
        }
        return VirtualminMailOperation.objects.create(**{**values, **overrides})

    def test_uncertain_work_excludes_a_second_attempt_for_the_account(self):
        first = self.operation(status="needs_review")
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.operation()
        first.refresh_from_db()
        self.assertEqual(first.status, "needs_review")

    def test_a_completed_attempt_does_not_reserve_the_account_forever(self):
        first = self.operation(status="completed")
        second = self.operation()
        self.assertNotEqual(first.pk, second.pk)

    def test_a_submission_uuid_cannot_be_reused_after_completion(self):
        first = self.operation(status="completed")
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.operation(submission_id=first.submission_id)

    def test_confirmed_intent_cannot_be_replaced_by_a_stale_worker(self):
        operation = self.operation()
        operation.confirmed_plan = {"version": 1, "records": [{"type": "MX", "name": "foreign.example"}]}
        with self.assertRaises(ValidationError):
            operation.save()
        with self.assertRaises(ValidationError):
            VirtualminMailOperation.objects.filter(pk=operation.pk).update(consent_digest="b" * 64)

    def test_invalid_operational_status_is_rejected_by_the_database(self):
        operation = self.operation()
        with self.assertRaises(IntegrityError), transaction.atomic():
            VirtualminMailOperation.objects.filter(pk=operation.pk).update(status="forgotten")

    def test_operation_audit_retains_owner_consent_without_recording_native_payloads(self):
        operation = self.operation()
        events = AuditEvent.objects.filter(action="configuration_changed", object_id=str(operation.pk))
        self.assertEqual(events.count(), 1)
        event = events.get()
        self.assertEqual(event.user_id, self.user.pk)
        self.assertEqual(event.new_values["consent_digest"], operation.consent_digest)
        self.assertNotIn("confirmed_plan", event.new_values)
        operation.lease_token = uuid4()
        operation.save(update_fields=["lease_token"])
        self.assertEqual(events.count(), 1, "A lease heartbeat is not another owner decision")
