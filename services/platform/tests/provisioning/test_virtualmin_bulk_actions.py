"""The Virtualmin bulk-actions page works, and its Suspend and Activate go through the Service (#566).

Until this change the page had never worked:
- `provisioning/virtualmin/bulk_actions.html` did not exist, so every GET was a 500;
- the form wanted a comma-separated hidden field that no UI filled;
- Suspend and Activate saved a `last_modified` field the model does not have.

Had they run, they would have flipped `VirtualminAccount.status` without calling Virtualmin.
They now loop over the same per-account helpers as the account page, so the reconciler stays
the single writer of the enabled state (ADR-0051).
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.http import HttpResponse
from django.urls import reverse

from apps.provisioning.models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.users.models import User
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_hosting_account_staff_actions import STAFF_TOKEN, _StaffButtonBase

BULK = "provisioning:virtualmin_bulk_actions"
ENQUEUE = "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async"
GATEWAY = "apps.provisioning.virtualmin_service.VirtualminGateway"


class _BulkBase(_StaffButtonBase):
    def setUp(self) -> None:
        super().setUp()
        self.account.status = "active"
        self.account.save(update_fields=["status"])
        self.second = self._hosted("second.example.com", server=self.server)

    def _hosted(self, name: str, *, server: VirtualminServer, status: str = "active") -> VirtualminAccount:
        username = name.split(".", 1)[0]
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=name,
            domain=name,
            username=username,
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="active",
        )
        return VirtualminAccount.objects.create(
            domain=name, service=service, server=server, virtualmin_username=username, status=status
        )

    def _post(
        self, action: str, accounts: list[VirtualminAccount], *, query: str = "", confirm: bool = True
    ) -> tuple[HttpResponse, MockVirtualminGateway, list[str]]:
        data: dict[str, object] = {"action": action, "selected_accounts": [str(a.pk) for a in accounts]}
        if action == "backup":
            data["backup_type"] = "full"  # the form requires it for a backup
        if confirm:
            data["confirm_bulk_action"] = "on"
        gateway = MockVirtualminGateway()
        for account in (self.account, self.second):
            gateway.seed_domain(account.domain, enabled=account.status == "active")
        with (
            patch(GATEWAY, return_value=gateway),
            patch(ENQUEUE) as enqueue,
            self.captureOnCommitCallbacks(execute=True),
        ):
            response = self.client.post(reverse(BULK) + query, data)
        return response, gateway, [call.args[0] for call in enqueue.call_args_list]


class BulkPageRendersTests(_BulkBase):
    def test_the_page_renders_one_checkbox_per_account(self) -> None:
        """FAILS on master: the template never existed, so this was a 500."""
        response = self.client.get(reverse(BULK))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "provisioning/virtualmin/bulk_actions.html")
        for account in (self.account, self.second):
            self.assertContains(response, f'value="{account.pk}"')

    def test_the_server_filter_narrows_the_list(self) -> None:
        """FAILS on master. The page uses the same filter name as the accounts list."""
        other_server = VirtualminServer.objects.create(
            name="other", hostname="other.example.com", api_username="api", status="active"
        )
        elsewhere = self._hosted("elsewhere.example.com", server=other_server)

        response = self.client.get(reverse(BULK), {"server": str(self.server.pk)})

        self.assertContains(response, f'value="{self.account.pk}"')
        self.assertNotContains(response, f'value="{elsewhere.pk}"')

    def test_select_all_ticks_every_listed_account(self) -> None:
        """FAILS on master. Done server-side, so the page needs no JavaScript."""
        response = self.client.get(reverse(BULK), {"select": "all"})

        self.assertEqual(set(response.context["selected_ids"]), {str(self.account.pk), str(self.second.pk)})

    def test_a_malformed_server_filter_is_a_bad_request(self) -> None:
        """FAILS on master: an invalid filter must answer 400, not 500."""
        response = self.client.get(reverse(BULK), {"server": "not-a-server"})

        self.assertEqual(response.status_code, 400)

    def test_a_non_staff_user_is_refused(self) -> None:
        """Guard: the page stays staff-only."""
        self.client.force_login(User.objects.create_user(email="not-staff@example.com", password="Not-staff-pass123!"))

        self.assertEqual(self.client.get(reverse(BULK)).status_code, 302)

    def test_the_accounts_list_links_to_the_page_with_its_filters(self) -> None:
        """FAILS on master: nothing linked to the page."""
        response = self.client.get(reverse("provisioning:virtualmin_accounts"), {"server": str(self.server.pk)})

        self.assertContains(response, f"{reverse(BULK)}?server={self.server.pk}")


class BulkFormValidationTests(_BulkBase):
    def test_a_missing_confirmation_changes_nothing_and_keeps_the_selection(self) -> None:
        response, gateway, queued = self._post("suspend", [self.account], confirm=False)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["form"].errors)
        self.assertEqual(response.context["selected_ids"], [str(self.account.pk)])
        self.assertEqual((gateway.get_calls(), queued), ([], []))
        self._assert_untouched(gateway, "active")

    def test_a_malformed_account_id_is_a_form_error_not_a_crash(self) -> None:
        response = self.client.post(
            reverse(BULK), {"action": "suspend", "selected_accounts": ["nope"], "confirm_bulk_action": "on"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("selected_accounts", response.context["form"].errors)

    def test_an_account_outside_the_current_filter_is_refused(self) -> None:
        """FAILS on master. The POST validates against the same filtered list as the GET."""
        other_server = VirtualminServer.objects.create(
            name="other", hostname="other.example.com", api_username="api", status="active"
        )
        elsewhere = self._hosted("elsewhere.example.com", server=other_server)

        response, _gateway, queued = self._post("suspend", [elsewhere], query=f"?server={self.server.pk}")

        self.assertIn("selected_accounts", response.context["form"].errors)
        self.assertEqual(queued, [])

    def test_a_health_check_over_the_concurrency_cap_is_refused(self) -> None:
        """FAILS on master. Every check must run in one wave, with nothing queued behind it.

        The cap is the `provisioning.max_concurrent_health_checks` setting (default 5), the
        same value the executor uses, not a hardcoded constant.
        """
        accounts = [self._hosted(f"cap{i}.example.com", server=self.server) for i in range(6)]

        response, _gateway, _queued = self._post("health_check", accounts)

        self.assertEqual(response.status_code, 200)
        self.assertIn("selected_accounts", response.context["form"].errors)


class BulkStaffActionsTests(_BulkBase):
    def test_bulk_suspend_suspends_each_service_and_never_calls_the_gateway(self) -> None:
        """FAILS on master: the page could not run, and its helper wrote a nonexistent field."""
        response, gateway, queued = self._post("suspend", [self.account, self.second])

        self.assertEqual(response.status_code, 302)
        self.assertEqual(gateway.get_calls(), [])
        for account in (self.account, self.second):
            account.service.refresh_from_db()
            self.assertEqual((account.service.status, account.service.suspension_reason), ("suspended", STAFF_TOKEN))
        self.assertEqual(sorted(queued), sorted([str(self.account.service_id), str(self.second.service_id)]))

    def test_bulk_activate_resumes_only_what_staff_suspended(self) -> None:
        """FAILS on master. One staff suspension resumes; billing's stays with billing."""
        for account, reason in ((self.account, STAFF_TOKEN), (self.second, "payment_overdue")):
            Service.objects.filter(pk=account.service_id).update(status="suspended", suspension_reason=reason)
            account.status = "suspended"
            account.save(update_fields=["status"])

        response, gateway, _queued = self._post("activate", [self.account, self.second])

        self.assertEqual(response.status_code, 302)
        self.assertEqual(gateway.get_calls(), [])
        self.assertEqual(Service.objects.get(pk=self.account.service_id).status, "active")
        self.assertEqual(Service.objects.get(pk=self.second.service_id).status, "suspended")


class BulkBackupAndHealthCheckTests(_BulkBase):
    def test_bulk_backup_admits_one_job_per_account(self) -> None:
        """Guard: backup already called the real admission path; now the page can reach it."""
        with patch("django_q.tasks.async_task") as queue_task:
            response, _gateway, _queued = self._post("backup", [self.account, self.second])

        self.assertEqual(response.status_code, 302)
        self.assertEqual(VirtualminProvisioningJob.objects.filter(operation="backup_domain").count(), 2)
        self.assertEqual(queue_task.call_count, 2)

    def test_health_check_runs_each_account_and_closes_each_worker_connection(self) -> None:
        """FAILS on master. Each pool thread's own database connection is closed."""
        with (
            patch("apps.provisioning.virtualmin_views.VirtualminGateway.ping_server", side_effect=[True, False]),
            patch("apps.provisioning.virtualmin_views.connections.close_all") as close_all,
        ):
            response, _gateway, _queued = self._post("health_check", [self.account, self.second])

        self.assertEqual(response.status_code, 302)
        self.assertEqual(close_all.call_count, 2)
