"""Staff retry a hosting line whose Virtualmin create gave up, and nothing else.

A real hosting failure leaves the Service active, the create job failed with no retry scheduled (or in attention),
and the order line failed. Nothing recovered it: the job retry refuses an exhausted job, staff completion refuses a
failed line, and recovery skips failed lines. retry_line_for_staff re-arms the job for one more attempt and reopens
the line in one transaction, under the fulfilment locks; fulfilment then moves the line as the job completes.

What it refuses, and why each matters:
- an order that isn't provisioning: cancellation leaves an already-failed line failed inside a cancelled order;
- a refunded order: refunds live on the invoice and payment, not on the order status;
- a suspended customer, an attention job (the node's state is unknown: resolve it first), a manual line (staff mark
  those fulfilled), a line that isn't failed (which also refuses a second click).
"""

from __future__ import annotations

from unittest.mock import patch

from django.test import Client
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.billing.refund_models import Refund
from apps.common.types import Retriability
from apps.customers.models import Customer
from apps.orders.hosting_fulfilment import fulfil_hosting_line, retry_line_for_staff
from apps.orders.models import Order
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status
from tests.orders.test_hosting_fulfilment import HostingLineCase

ASYNC = "django_q.tasks.async_task"


class RetryFailedLineCase(HostingLineCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = User.objects.create_user(email="retry-manager@example.test", is_staff=True, staff_role="manager")
        fulfil_hosting_line(self.line.pk)  # activates the Service
        self.account = self._account(status="error")
        self.job = self._job(self.account)
        self.job.retry_count = self.job.max_retries
        self.job.mark_failed("quota refused", retriability=Retriability.RETRIABLE)
        fulfil_hosting_line(self.line.pk)
        self._reload()
        self.assertEqual((self.line.provisioning_status, self.service.status), ("failed", "active"))
        self.assertIsNone(self.job.next_retry_at)

    def settled_refund(self) -> None:
        refund = Refund.objects.create(
            order=self.order,
            customer=self.customer,
            amount_cents=2999,
            original_amount_cents=2999,
            currency=self.currency,
            reference_number=f"REF-RETRY-{self.order.pk}",
        )
        force_status(refund, "completed")

    def retry(self) -> object:
        with patch(ASYNC) as queued, self.captureOnCommitCallbacks(execute=True):
            result = retry_line_for_staff(self.line.pk, actor=self.manager)
        self.queued = [call.args[0] for call in queued.call_args_list]
        return result


class RetryLineTests(RetryFailedLineCase):
    def test_the_job_gets_one_more_attempt_and_the_line_completes_with_it(self) -> None:
        self.assertEqual(self.retry().unwrap(), "retried")
        self.job.refresh_from_db()
        self._reload()
        self.assertIsNotNone(self.job.next_retry_at)
        self.assertEqual(self.job.retry_count, self.job.max_retries - 1)
        self.assertEqual(self.line.provisioning_status, "pending")
        self.assertEqual(self.service.status, "active")  # untouched
        self.assertEqual(
            self.queued,
            [
                "apps.provisioning.virtualmin_tasks.process_failed_virtualmin_jobs",
                "apps.orders.tasks.provision_order_item",
            ],
        )
        events = AuditEvent.objects.filter(action="provisioning_retried", object_id=str(self.line.pk))
        self.assertEqual(events.count(), 1)
        self.assertEqual(events.get().user, self.manager)

        # The line waits on the re-armed job, then completes with it.
        self.assertEqual(fulfil_hosting_line(self.line.pk).unwrap(), "in_progress")
        self.job.mark_completed({"domain": self.account.domain})
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="active")
        fulfil_hosting_line(self.line.pk)
        self._reload()
        self.assertEqual(self.line.provisioning_status, "completed")

    def test_a_second_retry_is_refused(self) -> None:
        self.retry().unwrap()
        self.assertIn("isn't failed", self.retry().unwrap_err())
        self.assertEqual(AuditEvent.objects.filter(action="provisioning_retried").count(), 1)

    def assert_refused(self, reason: str) -> None:
        result = self.retry()
        self.assertTrue(result.is_err())
        self.assertIn(reason, result.unwrap_err().lower())
        self.assertEqual(self.queued, [])
        self.line.refresh_from_db()
        self.assertEqual(self.line.provisioning_status, "failed")
        self.assertFalse(AuditEvent.objects.filter(action="provisioning_retried").exists())

    def test_an_attention_job_goes_to_its_resolution_first(self) -> None:
        self.job.mark_attention("lost the node's answer")
        self.assert_refused("resolve")

    def test_a_cancelled_order_is_refused(self) -> None:
        Order.objects.filter(pk=self.order.pk).update(status="cancelled")
        self.assert_refused("cancelled")

    def test_an_order_no_longer_provisioning_is_refused(self) -> None:
        Order.objects.filter(pk=self.order.pk).update(status="failed")
        self.assert_refused("being provisioned")

    def test_a_refunded_order_is_refused(self) -> None:
        self.settled_refund()
        self.assert_refused("refund")

    def test_a_suspended_customer_is_refused(self) -> None:
        Customer.objects.filter(pk=self.customer.pk).update(status="suspended")
        self.assert_refused("suspended")

    def test_a_line_praho_does_not_provision_is_left_to_staff(self) -> None:
        Service.objects.filter(pk=self.service.pk).update(domain="")
        self.assert_refused("fulfilled")


class RetryLineViewTests(RetryFailedLineCase):
    def url(self) -> str:
        return reverse("orders:order_item_retry", kwargs={"pk": self.order.pk, "item_pk": self.line.pk})

    def test_admin_and_manager_may_retry_and_land_on_the_order(self) -> None:
        client = Client()
        client.force_login(self.manager)
        with patch(ASYNC), self.captureOnCommitCallbacks(execute=True):
            response = client.post(self.url(), HTTP_HX_REQUEST="true")
        self.assertEqual(response["HX-Redirect"], reverse("orders:order_detail", kwargs={"pk": self.order.pk}))
        self.line.refresh_from_db()
        self.assertEqual(self.line.provisioning_status, "pending")

    def test_other_staff_and_a_get_are_refused(self) -> None:
        for role in ("support", "billing"):
            with self.subTest(role=role):
                client = Client()
                client.force_login(
                    User.objects.create_user(email=f"retry-{role}@example.test", is_staff=True, staff_role=role)
                )
                self.assertEqual(client.post(self.url()).status_code, 403)
        client = Client()
        client.force_login(self.manager)
        self.assertEqual(client.get(self.url()).status_code, 405)
        self.line.refresh_from_db()
        self.assertEqual(self.line.provisioning_status, "failed")


class ServiceActivateRefusesFailedTests(RetryFailedLineCase):
    def test_activate_does_not_revive_a_failed_service(self) -> None:
        """service_activate accepted failed (the FSM allows it) with no cancellation or suspension check."""
        Service.objects.filter(pk=self.service.pk).update(status="failed")
        admin = User.objects.create_user(email="activate-admin@example.test", is_staff=True, staff_role="admin")
        client = Client()
        client.force_login(admin)
        client.post(reverse("provisioning:service_activate", args=[self.service.pk]))
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "failed")


class RetryOnTheOrderPageTests(RetryFailedLineCase):
    """The order page offers Retry on a failed line, from the endpoint's own rules, or shows why not."""

    def retry_buttons(self, user: User) -> list[dict[str, str]]:
        from tests.ui.node_harness import Markup  # noqa: PLC0415

        client = Client()
        client.force_login(user)
        html = client.get(reverse("orders:order_detail", kwargs={"pk": self.order.pk})).content.decode()
        url = reverse("orders:order_item_retry", kwargs={"pk": self.order.pk, "item_pk": self.line.pk})
        retry = [
            a
            for t, a in Markup(html).elements
            if t == "button" and "Retry" in a.get("title", "") + a.get("hx-post", "")
        ]
        working = [a for t, a in Markup(html).elements if t == "button" and a.get("hx-post") == url]
        self.page = html
        return working or retry

    def test_a_manager_gets_a_working_retry(self) -> None:
        buttons = self.retry_buttons(self.manager)
        self.assertEqual(len(buttons), 1)
        self.assertNotIn("disabled", buttons[0])

    def test_other_staff_see_it_disabled_with_the_role_reason(self) -> None:
        support = User.objects.create_user(email="retry-page-support@example.test", is_staff=True, staff_role="support")
        self.retry_buttons(support)
        self.assertIn("Only admin or manager staff can retry a line.", self.page)
        self.assertNotIn(
            reverse("orders:order_item_retry", kwargs={"pk": self.order.pk, "item_pk": self.line.pk}), self.page
        )

    def test_an_attention_job_shows_the_way_to_resolve_it(self) -> None:
        self.job.mark_attention("lost the node's answer")
        self.retry_buttons(self.manager)
        self.assertIn("resolve it on the job page first", self.page)
        self.assertNotIn(
            reverse("orders:order_item_retry", kwargs={"pk": self.order.pk, "item_pk": self.line.pk}), self.page
        )


class ServicePageShowsTheWayTests(RetryFailedLineCase):
    """The service page's old Retry/Admin Notes buttons could never show and did nothing; it now points the way."""

    def page(self) -> str:
        client = Client()
        client.force_login(self.manager)
        return client.get(reverse("provisioning:service_detail", args=[self.service.pk])).content.decode()

    def test_a_failed_hosting_line_links_to_its_order_where_retry_lives(self) -> None:
        html = self.page()
        self.assertIn("Provisioning failed", html)
        self.assertIn(reverse("orders:order_detail", kwargs={"pk": self.order.pk}), html)
        self.assertNotIn("Add Admin Notes", html)

    def test_a_service_failed_by_cancellation_says_so_and_offers_no_retry(self) -> None:
        Order.objects.filter(pk=self.order.pk).update(status="cancelled")
        Service.objects.filter(pk=self.service.pk).update(status="failed")
        html = self.page()
        self.assertIn("Cancelled with its order", html)
        self.assertNotIn("Retry Provisioning", html)
