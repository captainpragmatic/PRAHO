"""Staff request real, scoped temporary relief through the existing native outbox."""

from datetime import timedelta

from django.test import Client, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Payment
from apps.customers.models import Customer
from apps.provisioning.hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from apps.provisioning.hosting_raise_models import ServiceHostingRaise
from apps.provisioning.hosting_raise_policy import MAX_RAISE_DURATION
from apps.tickets.models import Ticket
from apps.users.models import User
from tests.provisioning.test_hosting_raises import HostingRaiseFixture


class HostingRaiseViewTests(HostingRaiseFixture, TransactionTestCase):
    def test_extension_form_keeps_its_proposal_within_the_original_seven_day_limit(self) -> None:
        self.grant(expires_at=timezone.now() + timedelta(days=6, hours=12))
        row = ServiceHostingRaise.objects.get(service=self.service)
        self.client.force_login(self.staff)
        response = self.client.get(reverse("provisioning:service_hosting_raise", args=[self.service.pk]))
        self.assertEqual(response.status_code, 200)
        proposed = response.context["form"].initial["expires_at"]
        self.assertGreater(proposed, row.expires_at)
        self.assertLessEqual(proposed, row.first_granted_at + MAX_RAISE_DURATION)

    def test_raise_at_the_original_deadline_does_not_offer_an_impossible_extension(self) -> None:
        application = self.grant()
        self.assertEqual(self.apply(application), "completed")
        row = ServiceHostingRaise.objects.get(service=self.service)
        self.grant(expires_at=row.first_granted_at + MAX_RAISE_DURATION)
        self.client.force_login(self.staff)
        response = self.client.get(reverse("provisioning:service_hosting_raise", args=[self.service.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "This raise has reached its original seven-day limit.")
        self.assertNotContains(response, 'name="acknowledge_expiry"')
        self.assertContains(response, "Refresh usage check")

    def page_and_body(self, client):
        page = client.get(reverse("provisioning:service_detail", args=[self.service.pk]) + "temporary-relief/")
        self.assertEqual(page.status_code, 200, page.content)
        initial = page.context["form"].initial
        body = {
            "extra_mib": 1280,
            "ticket": self.ticket.pk,
            "reason": "Temporary incident relief for this customer",
            "expected_base_revision": initial["expected_base_revision"],
            "expected_overlay_revision": initial["expected_overlay_revision"],
            "submission_id": str(initial["submission_id"]),
            "expires_at": initial["expires_at"].isoformat(),
            "acknowledge_expiry": "on",
        }
        return page, body

    def test_actual_staff_form_enforces_csrf_and_replays_one_grant_without_billing_mutations(self) -> None:
        self.observe()
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.staff)
        page, body = self.page_and_body(client)
        path = page.request["PATH_INFO"]
        before_price, before_payments = self.service.price, Payment.objects.count()
        self.assertEqual(client.post(path, body).status_code, 403)
        self.assertFalse(ServiceHostingRaise.objects.exists())
        for _repeat in range(2):
            response = client.post(path, body, HTTP_X_CSRFTOKEN=page.cookies["csrftoken"].value)
            self.assertEqual(response.status_code, 302, response.content)
        row = ServiceHostingRaise.objects.get(service=self.service)
        self.assertEqual((row.extra_mib, row.revision, row.owner_id), (1280, 1, self.customer.pk))
        self.assertEqual(HostingLimitApplication.objects.filter(service=self.service, overlay_revision=1).count(), 1)
        self.service.refresh_from_db()
        self.assertEqual((self.service.price, Payment.objects.count()), (before_price, before_payments))
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).operational_disk_allowance_mib, 5120)

    def test_foreign_customer_ticket_and_billing_role_cannot_authorize_temporary_resources(self) -> None:
        self.client.force_login(self.staff)
        page, body = self.page_and_body(self.client)
        other = Customer.objects.create(name="Other relief customer", status="active")
        ticket = Ticket.objects.create(customer=other, title="Other customer incident", description="Outside scope")
        body["ticket"] = ticket.pk
        self.assertEqual(self.client.post(page.request["PATH_INFO"], body).status_code, 400)
        self.assertFalse(ServiceHostingRaise.objects.exists())
        billing = User.objects.create_user(email="relief-billing@example.test", staff_role="billing")
        self.client.force_login(billing)
        self.assertEqual(self.client.get(page.request["PATH_INFO"]).status_code, 403)
