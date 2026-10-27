"""DNS status and manual recheck cross the real signed Portal membership boundary."""

import json
import time
from decimal import Decimal
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.billing.currency_models import Currency
from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.provisioning import hosted_domain_dns_service as monitoring
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.hosted_domain_dns_models import HostedDomainDnsStatus
from apps.provisioning.service_models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "dns-api-tests"}}
IPV4 = "95.217.0.20"
IPV6 = "2a01:4f9:c010::20"
NODE = "private-node-monitor.example.net"
PRIVATE = "private-authority-trace-must-stay-in-platform"


@override_settings(CACHES=CACHE, PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class ServiceDnsStatusApiTests(HMACTestMixin, TestCase):
    def setUp(self):
        cache.clear()
        self.customer = Customer.objects.create(name="DNS API customer", primary_email="dns-owner@example.net", status="active")
        self.user = User.objects.create(email="dns-owner@example.net", is_active=True)
        self.membership = CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner")
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.plan = ServicePlan.objects.create(name="DNS hosting", price_monthly=Decimal("10.00"))
        self.service = self.make_service(self.customer)
        self.server = VirtualminServer.objects.create(name="DNS node", hostname=NODE, ipv4_address=IPV4, ipv6_address=IPV6)
        self.account = VirtualminAccount.objects.create(service=self.service, server=self.server, domain=self.service.domain,
                                                       virtualmin_username="dnsapitest", status="active")
        self.hostname = AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net",
            records={"A": {"intended": IPV4, "applied": IPV4, "ttl": 300}},
        )
        self.path = f"/api/services/{self.service.pk}/dns-status/"
        self.recheck = f"{self.path}recheck/"
        self.enterContext(patch("apps.provisioning.hosted_domain_dns_config.enabled", return_value=True))

    def make_service(self, customer, name="dns-api.example.net"):
        return Service.objects.create(customer=customer, service_plan=self.plan, currency_id="RON", service_name="Hosting",
                                      username=f"dnsapi{customer.pk}", domain=name, price=Decimal("10.00"), status="active")

    def identity(self, **extra):
        return {"customer_id": self.customer.pk, "user_id": self.user.pk, **extra}

    def healthy(self):
        claim, reason = monitoring.claim_check(str(self.account.pk))
        self.assertEqual(reason, "claimed")
        result = {"version": 1, "dns_path": "cname", "components": {
            name: {"state": "healthy", "code": "routing_reaches_account", "evidence": {
                "expected_ipv4": IPV4, "expected_ipv6": IPV6, "node": NODE, "trace": PRIVATE,
            }} for name in monitoring.COMPONENTS
        }}
        self.assertEqual(monitoring.commit_check(claim, result), "healthy")

    def test_signed_reads_and_rechecks_return_the_public_envelope_and_no_store(self):
        for path, expected in ((self.path, 200), (self.recheck, 202)):
            with self.subTest(path=path):
                response = self.portal_post(path, self.identity())
                self.assertEqual(response.status_code, expected, response.content)
                self.assertTrue(response.json()["success"])
                self.assertIn("dns_status", response.json()["data"])
                self.assertIn("no-store", response.headers.get("Cache-Control", ""))

    def test_any_active_membership_can_read_but_only_owner_and_tech_can_recheck(self):
        for role in ("viewer", "billing", "owner", "tech"):
            with self.subTest(role=role):
                self.membership.role = role
                self.membership.save(update_fields=["role"])
                self.assertEqual(self.portal_post(self.path, self.identity()).status_code, 200)
                response = self.portal_post(self.recheck, self.identity())
                self.assertEqual(response.status_code, 202 if role in {"owner", "tech"} else 403, response.content)

    def test_inactive_and_revoked_memberships_are_denied_by_both_endpoints(self):
        self.membership.is_active = False
        self.membership.save(update_fields=["is_active"])
        for path in (self.path, self.recheck):
            self.assertEqual(self.portal_post(path, self.identity()).status_code, 403)
        self.membership.delete()
        for path in (self.path, self.recheck):
            self.assertEqual(self.portal_post(path, self.identity()).status_code, 403)

    def test_an_inactive_user_cannot_read_or_recheck(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        for path in (self.path, self.recheck):
            self.assertEqual(self.portal_post(path, self.identity()).status_code, 401)

    def test_foreign_and_absent_services_are_uniform_404_before_account_lookup(self):
        foreign = self.make_service(Customer.objects.create(name="Other customer"), "foreign.example.net")
        with patch("apps.api.services.dns_views.VirtualminAccount.objects.filter") as accounts:
            for service_id in (foreign.pk, 999999):
                for suffix in ("", "recheck/"):
                    path = f"/api/services/{service_id}/dns-status/{suffix}"
                    response = self.portal_post(path, self.identity())
                    self.assertEqual(response.status_code, 404, response.content)
                    self.assertEqual(response.json(), {"success": False, "error": "Service not found"})
            accounts.assert_not_called()

    def test_signed_customer_identity_cannot_select_another_customers_service(self):
        other = Customer.objects.create(name="Other customer")
        response = self.portal_post(self.path, self.identity(customer_id=other.pk))
        self.assertEqual(response.status_code, 403)

    def test_unsigned_and_forged_requests_never_reach_monitoring(self):
        with patch("apps.provisioning.hosted_domain_dns_service.request_recheck") as recheck:
            for path in (self.path, self.recheck):
                self.assertEqual(self.client.post(path, b"{}", content_type="application/json").status_code, 401)
                self.assertEqual(self.portal_post(path, self.identity(), HTTP_X_SIGNATURE="0" * 64).status_code, 401)
            recheck.assert_not_called()

    def test_replayed_signed_request_is_rejected(self):
        body = json.dumps(self.identity(timestamp=time.time())).encode()
        headers = hmac_headers("POST", self.recheck, body, nonce="dns-test-replay-" + "a" * 32)
        first = self.client.post(self.recheck, body, content_type="application/json", **headers)
        second = self.client.post(self.recheck, body, content_type="application/json", **headers)
        self.assertEqual(first.status_code, 202, first.content)
        self.assertEqual(second.status_code, 401)

    def test_no_get_body_variant_is_introduced(self):
        for path in (self.path, self.recheck):
            self.assertEqual(self.portal_get(path, self.identity()).status_code, 405)

    def test_nonhosting_service_has_an_explicit_not_applicable_read_and_conflict_on_recheck(self):
        self.account.delete()
        response = self.portal_post(self.path, self.identity())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["data"]["dns_status"]["state"], "not_applicable")
        self.assertEqual(self.portal_post(self.recheck, self.identity()).status_code, 409)

    def test_read_and_recheck_never_call_dns_or_enqueue_an_inline_task(self):
        with (
            patch("apps.infrastructure.dns_probes.probe_hosted_domain_dns") as probe,
            patch("dns.query.tcp") as tcp,
            patch("django_q.tasks.async_task") as enqueue,
        ):
            self.assertEqual(self.portal_post(self.path, self.identity()).status_code, 200)
            self.assertFalse(HostedDomainDnsStatus.objects.filter(account=self.account).exists())
            self.assertEqual(self.portal_post(self.recheck, self.identity()).status_code, 202)
            probe.assert_not_called()
            tcp.assert_not_called()
            enqueue.assert_not_called()

    def test_private_dns_evidence_and_node_details_never_enter_the_customer_response(self):
        self.healthy()
        response = self.portal_post(self.path, self.identity())
        self.assertEqual(response.status_code, 200, response.content)
        public = response.json()["data"]["dns_status"]
        self.assertEqual(public["state"], "healthy")
        self.assertEqual(public["account_name"], self.hostname.fqdn)
        for secret in (IPV4, IPV6, NODE, PRIVATE, "evidence", "expected_generation", "lease_token"):
            self.assertNotIn(secret, response.content.decode())

    def test_recheck_receives_the_canonical_authenticated_user_and_ignores_posted_actor_ids(self):
        with patch("apps.provisioning.hosted_domain_dns_service.request_recheck", return_value=Ok({"pending": True, "queued": True})) as recheck:
            response = self.portal_post(self.recheck, self.identity(actor_id=9999, actor=None))
        self.assertEqual(response.status_code, 202, response.content)
        self.assertEqual(recheck.call_args.kwargs["actor"], self.user)

    def test_recheck_never_treats_a_missing_canonical_actor_as_an_internal_system_request(self):
        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.provisioning.hosted_domain_dns_service.request_recheck") as recheck,
        ):
            response = self.portal_post(self.recheck, self.identity())
        self.assertEqual(response.status_code, 403)
        recheck.assert_not_called()

    def test_backend_conflict_is_generic_and_never_returns_raw_provider_or_node_errors(self):
        with patch("apps.provisioning.hosted_domain_dns_service.request_recheck", return_value=Err(f"{NODE} {IPV4} {PRIVATE}")):
            response = self.portal_post(self.recheck, self.identity())
        self.assertEqual(response.status_code, 409)
        for secret in (NODE, IPV4, PRIVATE):
            self.assertNotIn(secret, response.content.decode())

    def test_fresh_rechecks_are_deduplicated_but_both_acknowledged(self):
        first = self.portal_post(self.recheck, self.identity())
        second = self.portal_post(self.recheck, self.identity())
        self.assertEqual((first.status_code, second.status_code), (202, 202))
        self.assertTrue(first.json()["data"]["dns_status"]["queued"])
        self.assertFalse(second.json()["data"]["dns_status"]["queued"])
        self.assertTrue(second.json()["data"]["dns_status"]["pending"])
        self.assertEqual(HostedDomainDnsStatus.objects.filter(account=self.account).count(), 1)

    def test_a_completed_recheck_in_cooldown_does_not_fabricate_outstanding_work(self):
        self.assertEqual(self.portal_post(self.recheck, self.identity()).status_code, 202)
        self.healthy()
        response = self.portal_post(self.recheck, self.identity())
        self.assertEqual(response.status_code, 202)
        public = response.json()["data"]["dns_status"]
        self.assertFalse(public["queued"])
        self.assertFalse(public["pending"])

    def test_a_target_generation_change_invalidates_old_green_on_read_without_running_a_worker(self):
        self.healthy()
        target = VirtualminServer.objects.create(name="Replacement", hostname="private-replacement.example.net", ipv4_address="95.217.0.30")
        VirtualminAccount.objects.filter(pk=self.account.pk).update(server=target)
        AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=target)
        with patch("apps.infrastructure.dns_probes.probe_hosted_domain_dns") as probe:
            response = self.portal_post(self.path, self.identity())
        public = response.json()["data"]["dns_status"]
        self.assertEqual(public["state"], "unknown")
        self.assertTrue(public["stale"])
        probe.assert_not_called()

    def test_maintenance_and_termination_never_leave_old_green_visible(self):
        self.healthy()
        VirtualminAccount.objects.filter(pk=self.account.pk).update(restore_hold=True)
        public = self.portal_post(self.path, self.identity()).json()["data"]["dns_status"]
        self.assertEqual(public["state"], "unknown")
        self.assertEqual(public["components"]["apex"]["code"], "maintenance")
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="terminated", restore_hold=False)
        public = self.portal_post(self.path, self.identity()).json()["data"]["dns_status"]
        self.assertEqual(public["state"], "not_applicable")
        self.assertEqual(public["instructions"], [])
