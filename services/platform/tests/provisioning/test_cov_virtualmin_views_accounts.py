"""Coverage additions for account filters, sync and lifecycle view outcomes."""

from __future__ import annotations

from typing import cast
from unittest.mock import patch
from uuid import uuid4

from django.http import HttpResponse
from django.urls import reverse
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.customers.models import Customer
from apps.provisioning.models import Service
from apps.provisioning.services import STAFF_ACCOUNT_SUSPENSION_REASON
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from tests.factories.core_factories import create_staff_user
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture

ENQUEUE = "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async"


class VirtualminAccountCoverageTests(VirtualminViewsFixture):
    def test_account_filters_match_domain_customer_status_and_server(self) -> None:
        url = reverse("provisioning:virtualmin_accounts")
        for query in (
            {"search": "  EXAMPLE  "},
            {"search": self.customer.name},
            {"status": "active", "server": str(self.server.pk)},
        ):
            with self.subTest(query=query):
                response = self.client.get(url, query)
                self.assertContains(response, self.account.domain)
                self.assertEqual([row["id"] for row in response.context["table_data"]], [self.account.pk])
        row = response.context["table_data"][0]
        self.assertEqual(row["customer"], self.customer.name)
        self.assertEqual(row["status"]["variant"], "success")
        self.assertEqual(
            row["actions"][1]["url"],
            reverse("provisioning:virtualmin_account_backup", args=[self.account.pk]),
        )

    def test_filters_exclude_nonmatching_accounts(self) -> None:
        for query in (
            {"status": "suspended"},
            {"server": str(uuid4())},
            {"search": "missing-tenant"},
        ):
            with self.subTest(query=query):
                response = self.client.get(reverse("provisioning:virtualmin_accounts"), query)
                self.assertContains(response, "No accounts found")
                self.assertEqual(response.context["table_data"], [])

    def test_account_new_get_and_invalid_post_render_form(self) -> None:
        url = reverse("provisioning:virtualmin_account_new")
        self.assertContains(self.client.get(url), 'name="domain"')
        response = self.client.post(url, {"domain": "invalid-domain"})
        self.assertContains(response, "Enter a valid domain name.")
        self.assertIn("domain", response.context["form"].errors)
        self.assertEqual(VirtualminAccount.objects.count(), 1)

    def test_sync_updates_domains_and_usage_from_multiline_response(self) -> None:
        self.payload["data"] = [
            {
                "name": self.account.domain,
                "values": {
                    "Username": [self.account.virtualmin_username],
                    "Status": ["Enabled"],
                    "Disk usage": ["12 MB"],
                    "Disk quota": ["256 MB"],
                },
            },
            {
                "name": "alias.example.com",
                "values": {"Username": [self.account.virtualmin_username], "Status": ["Enabled"]},
            },
            {"name": "ignored.example.com", "values": {"Username": ["ignored"], "Status": ["Disabled"]}},
        ]
        response = self.client.post(reverse("provisioning:virtualmin_accounts_sync"), HTTP_HX_REQUEST="true")
        self.assertContains(response, self.account.domain)
        self.account.refresh_from_db()
        self.assertEqual(self.account.domains, [self.account.domain, "alias.example.com"])
        self.assertEqual(self.account.current_disk_usage_mb, 12)
        self.assertEqual(self.account.disk_quota_mb, 256)
        self.assertIsNotNone(self.account.last_sync_at)
        self.assertFalse(VirtualminAccount.objects.filter(virtualmin_username="ignored").exists())
        self.assertIn("1 updated", self.messages(response))

    def test_sync_creates_account_for_an_existing_service(self) -> None:
        self.account.delete()
        self.payload["data"] = [
            {
                "name": self.service.domain,
                "values": {"Username": [self.service.username], "Status": ["Enabled"]},
            }
        ]
        response = self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
        self.assertRedirects(response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False)
        account = VirtualminAccount.objects.get(service=self.service)
        self.assertEqual(account.virtualmin_username, self.service.username)
        self.assertEqual(account.domains, [self.service.domain])
        self.assertEqual(account.server_id, self.server.pk)
        self.assertEqual(account.status, "active")
        self.assertIsNotNone(account.last_sync_at)
        self.assertIn("1 created", self.messages(response))

    def test_sync_preserves_primary_domain_when_listing_is_incomplete(self) -> None:
        self.payload["data"] = [
            {
                "name": "alias.example.com",
                "values": {"Username": [self.account.virtualmin_username], "Status": ["Enabled"]},
            }
        ]
        response = self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
        self.assertRedirects(response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False)
        self.account.refresh_from_db()
        self.assertEqual(self.account.domain, "test.example.com")
        self.assertIsNone(self.account.last_sync_at)
        self.assertIn("No new accounts found", self.messages(response))

    def test_sync_gateway_denial_leaves_usage_untouched(self) -> None:
        self.http_status = 403
        response = self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
        self.assertRedirects(response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False)
        self.account.refresh_from_db()
        self.assertIsNone(self.account.last_sync_at)
        self.assertEqual(self.account.current_disk_usage_mb, 0)
        self.assertIn("1 errors occurred", self.messages(response))

    def test_sync_without_active_servers_reports_problem(self) -> None:
        VirtualminServer.objects.update(status="disabled")
        response = self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
        self.assertRedirects(response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False)
        self.assertIn("No active Virtualmin servers found to sync from", self.messages(response))
        self.assertEqual(VirtualminAccount.objects.count(), 1)
        self.assertEqual(self.requests, [])

    def test_suspend_changes_service_and_queues_reconcile_without_calling_gateway(self) -> None:
        with patch(ENQUEUE) as enqueue, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("provisioning:virtualmin_account_suspend", args=[self.account.pk]))
            self.assertEqual(enqueue.call_args_list, [])
        self.assertRedirects(response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False)
        self.service.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual(
            (self.service.status, self.service.suspension_reason), ("suspended", STAFF_ACCOUNT_SUSPENSION_REASON)
        )
        self.assertEqual(self.account.status, "active")
        self.assertEqual([call.args for call in enqueue.call_args_list], [(str(self.service.pk),)])
        self.assertEqual(self.requests, [])
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())
        self.assertIn(
            "Suspension of testexample is queued; its service is suspended.",
            self.messages(cast(HttpResponse, response)),
        )

    def test_activate_resumes_service_and_returns_htmx_table_with_reconcile_queued(self) -> None:
        Service.objects.filter(pk=self.service.pk).update(
            status="suspended", suspension_reason=STAFF_ACCOUNT_SUSPENSION_REASON
        )
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        with patch(ENQUEUE) as enqueue, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("provisioning:virtualmin_account_activate", args=[self.account.pk]), HTTP_HX_REQUEST="true"
            )
            self.assertEqual(enqueue.call_args_list, [])
        self.assertContains(response, self.account.domain)
        self.assertTemplateUsed(response, "provisioning/virtualmin/partials/accounts_table.html")
        self.service.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual((self.service.status, self.service.suspension_reason), ("active", ""))
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual([call.args for call in enqueue.call_args_list], [(str(self.service.pk),)])
        self.assertEqual(self.requests, [])
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())
        self.assertIn("Activation of testexample is queued.", self.messages(cast(HttpResponse, response)))

    def test_detail_origin_htmx_lifecycle_redirects_and_queues_service_reconciliation(self) -> None:
        detail = reverse("provisioning:virtualmin_account_detail", args=[self.account.pk])
        for name, expected, reason in (
            ("virtualmin_account_suspend", "suspended", STAFF_ACCOUNT_SUSPENSION_REASON),
            ("virtualmin_account_activate", "active", ""),
        ):
            with self.subTest(name=name):
                with patch(ENQUEUE) as enqueue, self.captureOnCommitCallbacks(execute=True):
                    response = self.client.post(
                        reverse(f"provisioning:{name}", args=[self.account.pk]),
                        HTTP_HX_REQUEST="true",
                        HTTP_HX_CURRENT_URL=f"https://testserver{detail}",
                    )
                    self.assertEqual(enqueue.call_args_list, [])
                self.assertRedirects(response, detail, fetch_redirect_response=False)
                self.service.refresh_from_db()
                self.account.refresh_from_db()
                self.assertEqual((self.service.status, self.service.suspension_reason), (expected, reason))
                self.assertEqual(self.account.status, "active")
                self.assertEqual([call.args for call in enqueue.call_args_list], [(str(self.service.pk),)])
                self.assertEqual(self.requests, [])
                self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())

    def test_activate_refuses_suspended_customer_without_changing_state_or_queueing(self) -> None:
        Service.objects.filter(pk=self.service.pk).update(
            status="suspended", suspension_reason=STAFF_ACCOUNT_SUSPENSION_REASON
        )
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        Customer.objects.filter(pk=self.customer.pk).update(status="suspended")
        with patch(ENQUEUE) as enqueue, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("provisioning:virtualmin_account_activate", args=[self.account.pk]))
        self.assertRedirects(response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False)
        self.service.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual(
            (self.service.status, self.service.suspension_reason), ("suspended", STAFF_ACCOUNT_SUSPENSION_REASON)
        )
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(enqueue.call_args_list, [])
        self.assertEqual(self.requests, [])
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())
        self.assertIn(
            "The customer is suspended; reactivate the customer first.", self.messages(cast(HttpResponse, response))
        )

    def test_protection_toggle_persists_both_directions_and_returns_quick_actions(self) -> None:
        url = reverse("provisioning:virtualmin_account_toggle_protection", args=[self.account.pk])
        self.account.protected_from_deletion = True
        self.account.save(update_fields=["protected_from_deletion"])
        for expected in (False, True):
            with self.subTest(expected=expected):
                response = self.client.post(
                    url,
                    HTTP_HX_REQUEST="true",
                    HTTP_HX_CURRENT_URL=reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]),
                )
                self.assertContains(response, "Disable Protection" if expected else "Enable Protection")
                self.account.refresh_from_db()
                self.assertEqual(self.account.protected_from_deletion, expected)
                self.assertEqual(response.context["account"].protected_from_deletion, expected)

    def test_protected_delete_keeps_account_and_reports_refusal(self) -> None:
        self.account.protected_from_deletion = True
        self.account.save(update_fields=["protected_from_deletion"])
        response = self.client.post(reverse("provisioning:virtualmin_account_delete", args=[self.account.pk]))
        self.assertRedirects(response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "active")
        self.assertIn("protected from deletion", self.messages(response))
        self.assertEqual(self.requests, [])

    def test_delete_terminates_error_account_and_decrements_server_capacity(self) -> None:
        self.account.status = "error"
        self.account.protected_from_deletion = False
        self.account.save(update_fields=["status", "protected_from_deletion"])
        response = self.client.post(
            reverse("provisioning:virtualmin_account_delete", args=[self.account.pk]), HTTP_HX_REQUEST="true"
        )
        self.assertContains(response, self.account.domain)
        self.account.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(self.account.status, "terminated")
        self.assertEqual(self.server.current_domains, 9)
        self.assertEqual(
            VirtualminProvisioningJob.objects.get(account=self.account, operation="delete_domain").status, "completed"
        )

    def test_support_cannot_toggle_protection_or_delete_existing_account(self) -> None:
        self.client.force_login(create_staff_user("restricted-support"))
        for name in ("virtualmin_account_toggle_protection", "virtualmin_account_delete"):
            with self.subTest(name=name):
                response = self.client.post(reverse(f"provisioning:{name}", args=[self.account.pk]))
                self.assertEqual(response.status_code, 403)
                self.account.refresh_from_db()
                self.assertEqual(self.account.status, "active")
                self.assertTrue(VirtualminAccount.objects.filter(pk=self.account.pk).exists())
        self.assertEqual(self.requests, [])

    def test_bulk_lifecycle_changes_service_queues_reconcile_and_reports_refusals(self) -> None:
        url = reverse("provisioning:virtualmin_bulk_actions")
        for action, initial, expected in (
            ("suspend", "active", "suspended"),
            ("activate", "suspended", "active"),
        ):
            with self.subTest(action=action):
                Service.objects.filter(pk=self.service.pk).update(
                    status=initial,
                    suspension_reason=STAFF_ACCOUNT_SUSPENSION_REASON if initial == "suspended" else "",
                )
                self.account.status = initial
                self.account.save(update_fields=["status"])
                with patch(ENQUEUE) as enqueue, self.captureOnCommitCallbacks(execute=True):
                    response = self.client.post(
                        url,
                        {"action": action, "selected_accounts": [str(self.account.pk)], "confirm_bulk_action": "on"},
                    )
                    self.assertEqual(enqueue.call_args_list, [])
                self.assertRedirects(
                    response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False
                )
                self.service.refresh_from_db()
                self.account.refresh_from_db()
                self.assertEqual(self.service.status, expected)
                self.assertEqual(
                    self.service.suspension_reason, STAFF_ACCOUNT_SUSPENSION_REASON if action == "suspend" else ""
                )
                self.assertEqual(self.account.status, initial)
                self.assertEqual([call.args for call in enqueue.call_args_list], [(str(self.service.pk),)])
                self.assertEqual(self.requests, [])
                self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())
                self.assertIn(
                    "Queued 1 of 1 accounts; the reconciler applies each change.",
                    self.messages(cast(HttpResponse, response)),
                )

                refused_status = "pending" if action == "suspend" else "suspended"
                Service.objects.filter(pk=self.service.pk).update(
                    status=refused_status, suspension_reason="payment_overdue"
                )
                with patch(ENQUEUE) as enqueue, self.captureOnCommitCallbacks(execute=True):
                    response = self.client.post(
                        url,
                        {"action": action, "selected_accounts": [str(self.account.pk)], "confirm_bulk_action": "on"},
                    )
                self.assertRedirects(
                    response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False
                )
                self.service.refresh_from_db()
                self.account.refresh_from_db()
                self.assertEqual(
                    (self.service.status, self.service.suspension_reason), (refused_status, "payment_overdue")
                )
                self.assertEqual(self.account.status, initial)
                self.assertEqual(enqueue.call_args_list, [])
                self.assertEqual(self.requests, [])
                self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())
                self.assertIn("Queued 0 of 1 accounts", self.messages(cast(HttpResponse, response)))
                self.assertIn("1 refused:", self.messages(cast(HttpResponse, response)))
                self.assertIn(
                    "manage it from the service page"
                    if action == "suspend"
                    else "by another process (payment_overdue)",
                    self.messages(cast(HttpResponse, response)),
                )

    def test_bulk_backup_persists_job_and_signed_queue_payload(self) -> None:
        response = self.client.post(
            reverse("provisioning:virtualmin_bulk_actions"),
            {
                "action": "backup",
                "selected_accounts": str(self.account.pk),
                "confirm_bulk_action": "on",
                "backup_type": "config_only",
            },
        )
        self.assertRedirects(response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False)
        job = VirtualminProvisioningJob.objects.get(account=self.account, operation="backup_domain")
        self.assertEqual(job.status, "pending")
        self.assertEqual(job.parameters["backup_type"], "config_only")
        self.assertEqual(job.parameters["initiated_by"], "bulk_action")
        tasks = [cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()]
        task = next(
            task for task in tasks if task["func"] == "apps.provisioning.virtualmin_tasks.run_virtualmin_backup"
        )
        self.assertEqual(task["args"], (str(job.pk),))
        self.assertEqual(task["timeout"], job.parameters["task_budget_seconds"])
        self.assertIn("1/1 accounts", self.messages(response))

    def test_bulk_unknown_account_rerenders_selection_errors_without_side_effects(self) -> None:
        missing_id = str(uuid4())
        with patch(ENQUEUE) as enqueue, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("provisioning:virtualmin_bulk_actions"),
                {"action": "suspend", "selected_accounts": [missing_id], "confirm_bulk_action": "on"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "provisioning/virtualmin/bulk_actions.html")
        self.assertIn("selected_accounts", response.context["form"].errors)
        self.assertContains(response, "Select a valid choice.")
        self.assertEqual(response.context["selected_ids"], [missing_id])
        self.assertContains(response, self.account.domain)
        self.service.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual(self.service.status, "active")
        self.assertEqual(self.account.status, "active")
        self.assertEqual(enqueue.call_args_list, [])
        self.assertEqual(self.requests, [])
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())

    def test_bulk_health_reports_invalid_account_status_without_changing_it(self) -> None:
        self.account.status = "error"
        self.account.save(update_fields=["status"])
        response = self.client.post(
            reverse("provisioning:virtualmin_bulk_actions"),
            {"action": "health_check", "selected_accounts": str(self.account.pk), "confirm_bulk_action": "on"},
        )
        self.assertRedirects(response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "error")
        self.assertIn("0 healthy", self.messages(response))
        self.assertIn("1 accounts failed health checks", self.messages(response))
        self.assertEqual(self.requests, [])

    def test_account_new_persists_form_values_and_redirects(self) -> None:
        self.account.delete()
        response = self.client.post(
            reverse("provisioning:virtualmin_account_new"),
            {
                "domain": "coverage.test",
                "server": str(self.server.pk),
                "service": str(self.service.pk),
                "virtualmin_username": "coverageuser",
                "disk_quota_mb": "512",
                "bandwidth_quota_mb": "2048",
                "status": "provisioning",
            },
        )
        account = VirtualminAccount.objects.get(domain="coverage.test")
        self.assertRedirects(
            response,
            reverse("provisioning:virtualmin_account_detail", args=[account.pk]),
            fetch_redirect_response=False,
        )
        self.assertEqual(account.service_id, self.service.pk)
        self.assertEqual(account.server_id, self.server.pk)
        self.assertEqual(account.virtualmin_username, "coverageuser")
        self.assertEqual(account.disk_quota_mb, 512)
        self.assertEqual(account.bandwidth_quota_mb, 2048)
        self.assertEqual(account.status, "provisioning")

    def test_bulk_backup_conflict_reports_failure_and_preserves_pending_job(self) -> None:
        job = VirtualminProvisioningJob.objects.create(
            account=self.account, server=self.server, operation="backup_domain", status="pending"
        )
        response = self.client.post(
            reverse("provisioning:virtualmin_bulk_actions"),
            {
                "action": "backup",
                "selected_accounts": str(self.account.pk),
                "confirm_bulk_action": "on",
                "backup_type": "full",
            },
        )
        self.assertRedirects(response, reverse("provisioning:virtualmin_accounts"), fetch_redirect_response=False)
        self.assertEqual(list(VirtualminProvisioningJob.objects.values_list("pk", flat=True)), [job.pk])
        job.refresh_from_db()
        self.assertEqual(job.status, "pending")
        self.assertIn("0/1 accounts", self.messages(response))
        self.assertIn("1 backup operations failed", self.messages(response))
