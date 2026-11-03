"""Customer outputs use pinned allowances, never today's mutable catalog."""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.api.services.serializers import ServiceDetailSerializer, ServiceListSerializer
from apps.billing.models import BillingCycle, Currency
from apps.billing.subscription_currency_models import SubscriptionCurrencyTransition
from apps.billing.subscription_models import Subscription
from apps.customers.models import Customer
from apps.products.models import Product
from apps.provisioning import virtualmin_usage_service as usage
from apps.provisioning.hosting_limit_assignments import request_service_plan_change
from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_override_service import grant_resource_override
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_security import connection_identity
from apps.provisioning.virtualmin_usage_service import enabled
from apps.tickets.models import Ticket
from apps.users.models import CustomerMembership, User
from tests.helpers.fsm_helpers import force_status
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.provisioning.test_hosting_node_policy import quota_evidence
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class HostingLimitSurfaceTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(name="Pinned customer", customer_type="company", status="active")
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.plan = ServicePlan.objects.create(
            name="Assigned ten",
            plan_type="shared_hosting",
            price_monthly=Decimal("10.00"),
            disk_space_gb=10,
            bandwidth_gb=100,
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="Pinned hosting",
            domain="pinned.example.com",
            username="pinned",
            price=Decimal("10.00"),
            status="active",
            disk_usage_mb=5120,
            bandwidth_usage_mb=25600,
        )
        self.admin = User.objects.create_user(
            email="hosting-admin@example.com", password="testpass", staff_role="admin"
        )

    def test_resource_override_form_has_a_working_csrf_boundary(self) -> None:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        path = reverse("provisioning:service_resource_override", args=[self.service.pk])
        page = client.get(path)
        self.assertContains(page, 'name="csrfmiddlewaretoken"')
        refused = client.post(path, {})
        self.assertEqual(refused.status_code, 403)
        accepted = client.post(path, {"csrfmiddlewaretoken": client.cookies["csrftoken"].value})
        self.assertEqual(accepted.status_code, 400)
        self.assertContains(accepted, "This field is required", status_code=400)
        self.assertEqual(self.service.limit_applications.count(), 0)

    def test_catalog_edits_do_not_change_serialized_allowance_or_percentage(self) -> None:
        ServicePlan.objects.filter(pk=self.plan.pk).update(disk_space_gb=99, bandwidth_gb=999)
        service = Service.objects.select_related("hosting_limits", "service_plan", "customer", "currency").get(
            pk=self.service.pk
        )
        data = ServiceDetailSerializer(service).data
        self.assertEqual(data["disk_usage_percentage"], 50.0)
        self.assertEqual(data["bandwidth_usage_percentage"], 25.0)
        self.assertEqual(data["service_plan"]["disk_space_gb"], 10)
        self.assertEqual(data["features"]["bandwidth_gb"], 100)
        self.assertEqual(data["hosting_limits"]["assigned"]["disk_mib"], 10240)
        self.assertEqual(data["hosting_limits"]["state"], "unverified")
        self.assertNotIn("effective_disk", str(data["hosting_limits"]))

    def test_pending_assignment_retains_operational_allowance_and_saved_price(self) -> None:
        target = ServicePlan.objects.create(
            name="Requested twenty",
            plan_type="shared_hosting",
            price_monthly=Decimal("25"),
            disk_space_gb=20,
            bandwidth_gb=200,
        )
        with transaction.atomic():
            request_service_plan_change(
                service=self.service,
                target_plan_id=target.pk,
                expected_revision=1,
                submission_id=uuid4(),
                reason="Explicit resource-only exception",
                authority={"kind": "staff_resource_override"},
            )
        service = Service.objects.select_related("hosting_limits", "service_plan", "customer", "currency").get(
            pk=self.service.pk
        )
        data = ServiceDetailSerializer(service).data
        self.assertEqual(data["disk_usage_percentage"], 50.0)
        self.assertEqual(data["service_plan"]["disk_space_gb"], 10)
        self.assertEqual(data["monthly_price"], Decimal("10"))
        self.assertEqual(data["hosting_limits"]["assigned"]["disk_mib"], 20480)
        self.assertEqual(data["hosting_limits"]["operational"]["disk_mib"], 10240)
        self.assertEqual(data["hosting_limits"]["state"], "pending")
        self.assertIsNone(data["hosting_limits"]["verified"])
        self.assertEqual(ServiceListSerializer(service).data["hosting_limits"], data["hosting_limits"])

    def test_ordinary_edit_rejects_plan_change_with_clear_message(self) -> None:
        target = ServicePlan.objects.create(name="Other", plan_type="shared_hosting", price_monthly=20)
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("provisioning:service_edit", args=[self.service.pk]),
            {
                "customer_id": self.customer.pk,
                "plan_id": target.pk,
                "domain": self.service.domain,
            },
        )
        self.assertEqual(response.status_code, 409)
        self.assertContains(response, "resource-only exception", status_code=409)
        self.service.refresh_from_db()
        self.assertEqual(self.service.service_plan_id, self.plan.pk)

    def test_unknown_and_unlimited_have_no_percentage_and_remain_distinct(self) -> None:
        for amount in (None, 0):
            with self.subTest(amount=amount):
                ServiceHostingLimits.objects.filter(service=self.service).update(
                    disk_allowance_mib=amount,
                    operational_disk_allowance_mib=amount,
                )
                service = Service.objects.get(pk=self.service.pk)
                data = ServiceDetailSerializer(service).data
                self.assertIsNone(data["disk_usage_percentage"])
                self.assertEqual(data["hosting_limits"]["assigned"]["disk_mib"], amount)

    def test_batch_service_serialization_has_fixed_query_count(self) -> None:
        Service.objects.bulk_create(
            [
                Service(
                    customer=self.customer,
                    service_plan=self.plan,
                    currency=self.currency,
                    service_name=f"Batch {index}",
                    domain=f"batch{index}.example.com",
                    username=f"batch{index}",
                    price=10,
                    status="active",
                )
                for index in range(4)
            ]
        )
        queryset = Service.objects.select_related("hosting_limits", "service_plan", "customer", "currency")
        for identifiers in ([self.service.pk], list(queryset.values_list("pk", flat=True))):
            # Root/account reads, one overlay batch and two warning reads;
            # no account IDs means the warning cursor query needs no SQL.
            with self.assertNumQueries(5) as queries:
                values = ServiceListSerializer(queryset.filter(pk__in=identifiers), many=True).data
            self.assertEqual(len(values), len(identifiers))
            self.assertEqual({value["hosting_limits"]["assigned"]["disk_mib"] for value in values}, {10240})
            self.assertTrue(all("hosting_warnings" in value and "hosting_raise" in value for value in values))
            self.assertEqual(sum("provisioning_service_hosting_raise" in row["sql"] for row in queries.captured_queries), 1)

    def test_explicit_override_requires_authority_ticket_ack_and_replays_once(self) -> None:
        target = ServicePlan.objects.create(
            name="Exception twenty", plan_type="shared_hosting", price_monthly=50, disk_space_gb=20
        )
        ticket = Ticket.objects.create(
            customer=self.customer, title="Resource exception", description="Approved exception"
        )
        self.client.force_login(self.admin)
        url = reverse("provisioning:service_resource_override", args=[self.service.pk])
        payload = {
            "target_plan": target.pk,
            "ticket": ticket.pk,
            "reason": "Approved goodwill exception",
            "expected_revision": 1,
            "submission_id": str(uuid4()),
            "billing_unchanged": "on",
        }
        response = self.client.post(url, payload)
        self.assertEqual(response.status_code, 302)
        replay = self.client.post(url, payload)
        self.assertEqual(replay.status_code, 302)
        self.service.refresh_from_db()
        self.assertEqual(self.service.service_plan_id, target.pk)
        self.assertEqual(self.service.price, Decimal("10"))
        self.assertEqual(self.service.hosting_limits.revision, 2)
        self.assertEqual(self.service.limit_applications.count(), 1)
        application = self.service.limit_applications.get()
        self.assertEqual(application.authority["ticket_id"], str(ticket.pk))
        self.assertEqual(application.authority["billing_unchanged"], "acknowledged")
        page = self.client.get(reverse("provisioning:service_detail", args=[self.service.pk]))
        self.assertContains(page, "Requested allowance")
        self.assertContains(page, "not yet verified")
        listing = self.client.get(reverse("provisioning:services"))
        self.assertContains(listing, "Limits pending")

    def test_override_refuses_support_role_cross_customer_ticket_and_missing_ack(self) -> None:
        support = User.objects.create_user(
            email="hosting-support@example.com", password="testpass", staff_role="support"
        )
        other = Customer.objects.create(name="Other customer", customer_type="company", status="active")
        ticket = Ticket.objects.create(customer=other, title="Other ticket", description="Unrelated")
        url = reverse("provisioning:service_resource_override", args=[self.service.pk])
        self.client.force_login(support)
        self.assertEqual(self.client.get(url).status_code, 403)
        self.client.force_login(self.admin)
        payload = {
            "target_plan": self.plan.pk,
            "ticket": ticket.pk,
            "reason": "Invalid authority",
            "expected_revision": 1,
            "submission_id": str(uuid4()),
            "billing_unchanged": "on",
        }
        self.assertEqual(self.client.post(url, payload).status_code, 400)
        ticket.customer = self.customer
        ticket.save(update_fields=["customer"])
        payload.pop("billing_unchanged")
        self.assertEqual(self.client.post(url, payload).status_code, 400)
        self.assertEqual(self.service.limit_applications.count(), 0)

    def _override_arguments(self) -> dict[str, object]:
        ticket = Ticket.objects.create(
            customer=self.customer, title="Approved resources", description="Resource exception"
        )
        return {
            "user": self.admin,
            "service": self.service,
            "target_plan_id": self.plan.pk,
            "ticket_id": ticket.pk,
            "reason": "Approved temporary business exception",
            "expected_revision": 1,
            "submission_id": uuid4(),
            "billing_unchanged": True,
        }

    def test_override_refuses_stale_revision_and_submission_reuse_with_different_terms(self) -> None:
        arguments = self._override_arguments()
        with self.assertRaises(ValidationError):
            grant_resource_override(**{**arguments, "expected_revision": 9})
        first = grant_resource_override(**arguments)
        with self.assertRaises(ValidationError):
            grant_resource_override(**{**arguments, "reason": "Different authority"})
        self.assertEqual(grant_resource_override(**arguments).pk, first.pk)
        self.assertEqual(self.service.limit_applications.count(), 1)

    def test_override_keeps_subscription_price_and_refuses_active_currency_offer(self) -> None:
        product = Product.objects.create(
            slug="pinned-resources",
            name="Purchased hosting",
            product_type="shared_hosting",
            default_service_plan=self.plan,
        )
        now = timezone.now()
        subscription = Subscription.objects.create(
            customer=self.customer,
            service=self.service,
            product=product,
            currency=self.currency,
            subscription_number="SUB-PINNED",
            status="active",
            unit_price_cents=731,
            locked_price_cents=731,
            billing_cycle="monthly",
            quantity=1,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )
        arguments = self._override_arguments()
        target = ServicePlan.objects.create(
            name="Goodwill resources", plan_type="shared_hosting", price_monthly=50, disk_space_gb=20, bandwidth_gb=200
        )
        arguments["target_plan_id"] = target.pk
        cycle = BillingCycle.objects.create(
            subscription=subscription,
            period_start=now,
            period_end=now + timedelta(days=30),
            currency=self.currency,
            quantity=1,
            unit_price_cents=731,
            terms_frozen_at=now,
            pricing_snapshot={"purchased_tariff": {"unit_price_cents": 731, "product_id": str(product.pk)}},
        )
        frozen = BillingCycle.objects.filter(pk=cycle.pk).values().get()
        offer = SubscriptionCurrencyTransition.objects.create(
            subscription=subscription,
            policy_revision=1,
            old_terms={},
            target_terms={},
            target_fingerprint="a" * 64,
            notice_subject="Currency review",
            notice_body="Frozen monetary promise",
        )
        with self.assertRaisesMessage(ValidationError, "currency transition"):
            grant_resource_override(**arguments)
        self.assertEqual(self.service.limit_applications.count(), 0)
        SubscriptionCurrencyTransition.objects.filter(pk=offer.pk).update(status="superseded")
        grant_resource_override(**arguments)
        subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual((subscription.unit_price_cents, subscription.locked_price_cents), (731, 731))
        self.assertEqual(subscription.current_period_end, now + timedelta(days=30))
        self.assertEqual(self.service.price, Decimal("10"))
        self.assertEqual(self.service.service_plan_id, target.pk)
        self.assertEqual(BillingCycle.objects.filter(pk=cycle.pk).values().get(), frozen)
        product.refresh_from_db()
        self.assertEqual(product.default_service_plan_id, self.plan.pk)

    def test_ordinary_edit_preserves_owner_transfer_and_domain_edit_without_plan_field(self) -> None:
        other = Customer.objects.create(name="New owner", customer_type="company", status="active")
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("provisioning:service_edit", args=[self.service.pk]),
            {
                "customer_id": other.pk,
                "domain": "new-owner.example.com",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.service.refresh_from_db()
        self.assertEqual(self.service.customer_id, other.pk)
        self.assertEqual(self.service.domain, "new-owner.example.com")
        self.assertEqual(self.service.service_plan_id, self.plan.pk)
        self.assertEqual(self.service.price, Decimal("10"))


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, LANGUAGE_CODE="en")
class VerifiedHostingLimitSurfaceTests(HMACTestMixin, VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.create_user(email="verified-limit-owner@example.com")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_active=True)
        evidence = quota_evidence()
        evidence["identity"] = connection_identity(self.server)
        self.policy = NodeHostingPolicy.objects.create(
            server=self.server,
            connection_identity=evidence["identity"],
            quota_adopted=True,
            quota_verified_at=timezone.now(),
            quota_evidence=evidence,
        )
        self.identity = {key: evidence[key] for key in ("installation", "filesystem_uuid", "boot_id")}
        self.identity.update(domain_id="12345", domain=self.account.domain, uid=1001, gid=1001)
        target = ServicePlan.objects.create(
            name="Verified five", plan_type="shared_hosting", price_monthly=25, disk_space_gb=5, bandwidth_gb=20
        )
        actor = User.objects.create_user(email="native-adoption-staff@example.com", staff_role="admin")
        ticket = Ticket.objects.create(customer=self.customer, title="Adopt quota enforcement", description="Reviewed")
        self.application = grant_resource_override(
            user=actor,
            service=self.service,
            target_plan_id=target.pk,
            expected_revision=1,
            submission_id=uuid4(),
            reason="Explicitly adopt this existing account's native enforcement",
            ticket_id=ticket.pk,
            billing_unchanged=True,
            adopt_existing_native_limits=True,
        )

    def receipt(self, cap: int, request=None):
        value = {
            "schema": 1,
            "identity": self.identity,
            "observed_at": timezone.now().isoformat(),
            "filesystem": "ext4",
            "storage_qualified": True,
            "uid_enforced": True,
            "gid_enforced": True,
            "uid_soft_kib": cap * 1024,
            "uid_hard_kib": cap * 1024,
            "gid_soft_kib": cap * 1024,
            "gid_hard_kib": cap * 1024,
            "uid_used_bytes": 2048,
            "gid_used_bytes": 4096,
            "available_bytes": 10 * 1024**3,
            "configured_quota_kib": cap * 1024,
            "configured_uquota_kib": cap * 1024,
            "configured_bandwidth_bytes": 20 * 1024**3,
            "bandwidth_actions_safe": True,
        }
        if request:
            value.update(token=request["token"], generation=request["generation"])
        return value

    def apply(self) -> None:
        self.publish_usage(1, 1)
        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt(1024)),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=lambda server, action, request: self.receipt(request["disk_limit_kib"] // 1024, request),
            ),
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "completed")

    def publish_usage(self, files_mib: int, database_mib: int) -> None:
        force_status(self.account, "active")
        usage.current_state(self.account)
        now = timezone.now().isoformat()
        payload = {
            "version": 1,
            "installation": self.identity["installation"],
            "observed_at": now,
            "records": [
                {
                    "domain": self.account.domain,
                    "username": self.account.virtualmin_username,
                    "domain_id": "12345",
                    "scan_started_at": now,
                    "scan_finished_at": now,
                    "disk_files_bytes": files_mib * 1024**2,
                    "disk_db_bytes": database_mib * 1024**2,
                    "databases": 1,
                    "mailboxes": 0,
                    "segments": [],
                }
            ],
        }
        usage.publish_snapshot(self.server.pk, payload, usage.capture(self.server))

    def detail(self):
        return ServiceDetailSerializer(
            Service.objects.select_related("hosting_limits", "service_plan", "customer", "currency").get(
                pk=self.service.pk
            )
        ).data

    def test_verified_receipt_has_current_identity_and_no_customer_headroom(self) -> None:
        self.apply()
        self.publish_usage(4736, 128)
        data = self.detail()
        self.assertEqual(data["hosting_limits"]["state"], "verified")
        self.assertEqual(data["hosting_limits"]["operational"]["disk_mib"], 5120)
        self.assertEqual(data["hosting_limits"]["verified"]["disk_mib"], 5120)
        self.assertEqual(data["disk_usage_percentage"], 95.0)
        response = self.portal_post(
            f"/api/services/{self.service.pk}/usage/",
            {
                "customer_id": self.customer.pk,
                "user_id": self.user.pk,
                "action": "get_usage_stats",
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        measured = response.json()["data"]["usage"]
        self.assertEqual(measured["hosting_limits"]["state"], "verified")
        self.assertEqual(measured["current_usage"]["disk_usage_percentage"], 95.0)
        self.assertNotIn("5632", str(data["hosting_limits"]))
        self.server.hostname = "changed-node.example.com"
        self.server.save(update_fields=["hostname"])
        changed = self.detail()
        self.assertEqual(changed["hosting_limits"]["state"], "unverified")
        self.assertEqual(changed["hosting_limits"]["verified"]["disk_mib"], 5120)

    def test_verified_batch_has_fixed_queries_and_retains_operational_allowance(self) -> None:
        self.apply()
        Service.objects.bulk_create(
            [
                Service(
                    customer=self.customer,
                    service_plan=self.plan,
                    currency=self.currency,
                    service_name=f"More {index}",
                    domain=f"more{index}.example.com",
                    username=f"more{index}",
                    price=10,
                    status="active",
                )
                for index in range(4)
            ]
        )
        queryset = Service.objects.select_related("hosting_limits", "service_plan", "customer", "currency")
        enabled()
        for identifiers in ([self.service.pk], list(queryset.values_list("pk", flat=True))):
            # The eight proof/overlay reads plus three warning reads remain
            # fixed for one or five rows. Raise output reuses the overlay batch.
            with self.assertNumQueries(11) as queries:
                values = ServiceListSerializer(queryset.filter(pk__in=identifiers), many=True).data
            self.assertEqual(len(values), len(identifiers))
            self.assertEqual(sum("provisioning_service_hosting_raise" in row["sql"] for row in queries.captured_queries), 1)
            verified = [value for value in values if value["hosting_limits"]["state"] == "verified"]
            self.assertEqual(len(verified), 1)
            self.assertEqual(verified[0]["hosting_limits"]["assigned"]["disk_mib"], 5120)
