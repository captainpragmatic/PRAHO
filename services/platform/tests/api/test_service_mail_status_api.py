"""Mail status crosses the real signed customer boundary without execution or DNS work."""

import json
import time
from unittest.mock import patch
from uuid import uuid4

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.models import Customer
from apps.provisioning.virtualmin_mail_models import (
    VirtualminMailConfiguration,
    VirtualminMailOperation,
    mail_generation,
)
from apps.users.models import CustomerMembership, User
from tests.helpers.fsm_helpers import force_status
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers
from tests.provisioning.test_virtualmin_mail_models import MailModelFixture

PRIVATE = "private-mail-result-must-stay-on-platform"
CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "mail-api-tests"}}


@override_settings(CACHES=CACHE, PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class ServiceMailStatusApiTests(HMACTestMixin, MailModelFixture, TestCase):
    def setUp(self):
        self.enterContext(patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async"))
        super().setUp()
        cache.clear()
        self.customer = self.account.service.customer
        force_status(self.customer, "active")
        self.user = User.objects.create_user(email="mail-status-owner@example.test", password="Status-test123!")
        self.membership = CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner")
        self.path = f"/api/services/{self.account.service_id}/mail-status/"
        self.boundaries = []
        for boundary in (
            "apps.provisioning.virtualmin_gateway.VirtualminGateway.call",
            "apps.infrastructure.ansible_service.AnsibleService.run_playbook",
            "apps.infrastructure.dns_zone_gateway.get_zone_gateway",
            "dns.query.tcp",
            "dns.query.udp",
            "django_q.tasks.async_task",
        ):
            self.boundaries.append(self.enterContext(patch(boundary, side_effect=AssertionError("Read-only status"))))

    def tearDown(self):
        for boundary in self.boundaries:
            boundary.assert_not_called()
        super().tearDown()

    def identity(self, **extra):
        return {"customer_id": self.customer.pk, "user_id": self.user.pk, **extra}

    def public(self, **identity):
        response = self.portal_get(self.path, self.identity(**identity))
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        return response.json()["data"]["mail_status"]

    def operation(self, configuration, **extra):
        return VirtualminMailOperation.objects.create(
            configuration=configuration,
            requested_customer=self.customer,
            requested_by=self.user,
            submission_id=uuid4(),
            intent=extra.pop("intent", "enable"),
            target_generation=mail_generation(self.account),
            consent_digest="a" * 64,
            confirmed_plan={"private": PRIVATE},
            **extra,
        )

    def test_signed_get_without_configuration_reports_managed_external_intent_without_creating_rows(self):
        result = self.public()
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["applicability"], "applicable")
        self.assertEqual(result["mode"], "external")
        self.assertFalse(result["enrolled"])
        self.assertEqual(result["verification"], "unverified")
        self.assertIsNone(result["operation"])
        self.assertEqual(result["account_name"], self.name.fqdn)
        self.assertEqual(result["client_ports"], {"imap_tls": 993, "pop3_tls": 995, "submission_tls": 465})
        self.assertIsNone(result["verified_login"])
        self.assertNotIn("mx", result)
        self.assertNotIn("native_enabled", result)
        self.assertFalse(VirtualminMailConfiguration.objects.filter(account=self.account).exists())
        self.assertFalse(VirtualminMailOperation.objects.exists())

    def test_all_active_hosting_view_roles_can_read_and_owner_consent_is_explicit(self):
        for role in ("owner", "tech", "billing", "viewer"):
            with self.subTest(role=role):
                self.membership.role = role
                self.membership.save(update_fields=["role"])
                self.assertTrue(self.public()["requires_owner_consent"])

    def test_missing_signed_identity_and_revoked_current_user_or_membership_are_refused(self):
        for identity in ({"customer_id": self.customer.pk}, {"user_id": self.user.pk}, {}):
            with self.subTest(identity=identity):
                self.assertEqual(self.portal_get(self.path, identity).status_code, 400)
        self.membership.is_active = False
        self.membership.save(update_fields=["is_active"])
        self.assertEqual(self.portal_get(self.path, self.identity()).status_code, 403)
        self.membership.is_active = True
        self.membership.save(update_fields=["is_active"])
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertTrue(self.user.is_active)
        self.assertEqual(self.portal_get(self.path, self.identity()).status_code, 401)

    def test_foreign_or_absent_service_has_the_same_tenant_scoped_not_found_response(self):
        other = Customer.objects.create(name="Other mail customer", status="active")
        self.account.service.customer = other
        self.account.service.save(update_fields=["customer"])
        replies = []
        for identifier in (self.account.service_id, 99999999):
            response = self.portal_get(f"/api/services/{identifier}/mail-status/", self.identity())
            self.assertEqual(response.status_code, 404, response.content)
            replies.append(response.json())
        self.assertEqual(replies[0], replies[1])
        self.assertEqual(self.portal_get(self.path, self.identity(customer_id=other.pk)).status_code, 403)

    def test_unsigned_forged_and_replayed_signed_reads_never_reach_the_projection(self):
        self.assertEqual(self.client.get(self.path).status_code, 401)
        self.assertEqual(self.portal_get(self.path, self.identity(), HTTP_X_SIGNATURE="0" * 64).status_code, 401)
        body = json.dumps(self.identity(timestamp=time.time())).encode()
        headers = hmac_headers("GET", self.path, body, nonce="mail-read-replay-" + "a" * 32)
        first = self.client.generic("GET", self.path, body, content_type="application/json", **headers)
        second = self.client.generic("GET", self.path, body, content_type="application/json", **headers)
        self.assertEqual((first.status_code, second.status_code), (200, 401))

    def test_only_bounded_operation_fields_are_public_and_unknown_phase_or_error_are_fixed(self):
        configuration = VirtualminMailConfiguration.objects.create(
            account=self.account, proposal={"secret": PRIVATE}, retirement={"private_ref": PRIVATE}
        )
        operation = self.operation(
            configuration,
            status="running",
            checkpoint=PRIVATE,
            error_code=PRIVATE,
            result={"credentials": PRIVATE, "node": self.server.hostname},
            lease_token=uuid4(),
            lease_expires_at=timezone.now(),
        )
        public = self.public()
        self.assertEqual(public["operation"]["status"], "running")
        self.assertEqual(public["operation"]["intent"], "enable")
        self.assertEqual(public["operation"]["checkpoint"], "unknown")
        self.assertEqual(public["operation"]["error_code"], "mail_operation_unrecognized")
        self.assertEqual(public["operation"]["created_at"], operation.created_at.isoformat())
        for private in (
            PRIVATE,
            "lease_token",
            "lease_expires_at",
            "consent_digest",
            "confirmed_plan",
            "proposal",
            "result",
            "private_key_ref",
            self.server.hostname,
            self.server.ipv4_address,
            self.account.virtualmin_username,
        ):
            self.assertNotIn(private, json.dumps(public))

    def test_a_retirement_attempt_projects_intent_without_claiming_the_mode_has_already_changed(self):
        configuration = self.prepared()
        configuration.enable_hosted()
        configuration.save()
        self.operation(
            configuration,
            intent="disable",
            status="needs_review",
            checkpoint="native_inflight",
            error_code="mail_native_outcome_unknown",
        )
        result = self.public()
        self.assertEqual((result["mode"], result["enrolled"]), ("hosted", True))
        self.assertEqual(result["operation"]["intent"], "disable")
        self.assertEqual(result["operation"]["status"], "needs_review")

    def test_hosted_mode_survives_generation_drift_but_stale_verification_is_never_ready(self):
        configuration = self.prepared()
        configuration.enable_hosted()
        configuration.save()
        recorded_generation = configuration.readiness["generation"]
        current = self.public()
        self.assertEqual((current["mode"], current["enrolled"], current["verification"]), ("hosted", True, "current"))
        self.server.ipv4_address = "203.0.113.99"
        self.server.save(update_fields=["ipv4_address"])
        stale = self.public()
        self.assertEqual((stale["mode"], stale["enrolled"], stale["verification"]), ("hosted", True, "stale"))
        configuration.refresh_from_db()
        self.assertEqual(configuration.mode, "hosted")
        self.assertEqual(configuration.readiness["generation"], recorded_generation)
        self.assertNotEqual(mail_generation(self.account), recorded_generation)

    def test_new_customer_does_not_see_the_previous_customers_operation(self):
        configuration = VirtualminMailConfiguration.objects.create(account=self.account)
        self.operation(
            configuration, status="needs_review", checkpoint="native_inflight", error_code="mail_native_outcome_unknown"
        )
        other = Customer.objects.create(name="New mail customer", status="active")
        CustomerMembership.objects.create(user=self.user, customer=other, role="viewer")
        self.account.service.customer = other
        self.account.service.save(update_fields=["customer"])
        result = self.public(customer_id=other.pk)
        self.assertIsNone(result["operation"])

    def test_missing_canonical_actor_is_never_a_system_read(self):
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = self.portal_get(self.path, self.identity())
        self.assertEqual(response.status_code, 403)

    def test_nonhosting_read_is_not_applicable_and_does_not_create_configuration(self):
        self.account.delete()
        result = self.public()
        self.assertEqual(result["applicability"], "not_applicable")
        self.assertIsNone(result["account_name"])
        self.assertEqual(result["client_ports"], {})
        self.assertFalse(VirtualminMailConfiguration.objects.exists())

    def test_no_mutation_or_enable_stub_is_exposed(self):
        self.assertEqual(self.portal_post(self.path, self.identity()).status_code, 405)
        self.assertEqual(self.portal_post(f"{self.path}enable/", self.identity()).status_code, 404)
        self.assertFalse(VirtualminMailConfiguration.objects.exists())
