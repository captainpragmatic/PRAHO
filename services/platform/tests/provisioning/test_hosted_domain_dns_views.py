"""Staff pages display recorded DNS evidence without probing during requests."""

from unittest.mock import patch

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from apps.common.types import Ok
from apps.provisioning.hosted_domain_dns_models import HostedDomainDnsStatus
from apps.users.models import User
from tests.provisioning.test_account_hostname_lifecycle import _distinct_account
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class HostedDnsStaffViewsTests(MigrationTestBase):
    path = "/provisioning/virtualmin/dns-checks/"

    def setUp(self):
        super().setUp()
        self.client.force_login(self.staff)
        self.row = HostedDomainDnsStatus.objects.create(
            account=self.account,
            healthy=False,
            checked_at=timezone.now(),
            results={
                "components": {
                    "www": {"state": "broken", "code": "address_mismatch", "evidence": {"address": "203.0.113.77"}}
                }
            },
        )
        self.enterContext(
            patch("apps.infrastructure.dns_probes.probe_hosted_domain_dns", side_effect=AssertionError("Request DNS"))
        )
        self.enterContext(
            patch(
                "apps.provisioning.virtualmin_backup_service.VirtualminBackupService.list_backups", return_value=Ok([])
            )
        )

    def test_staff_list_shows_recorded_problem_and_check_time(self):
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.account.domain)
        self.assertContains(response, "Recorded DNS issues")
        self.assertContains(response, "Last checked")

    def test_unknown_filter_does_not_mix_recorded_broken_rows(self):
        response = self.client.get(self.path + "?state=unknown")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.account.domain)
        HostedDomainDnsStatus.objects.filter(pk=self.row.pk).update(healthy=None)
        self.assertContains(self.client.get(self.path + "?state=unknown"), self.account.domain)

    def test_account_panel_shows_bounded_escaped_private_evidence_to_staff(self):
        self.row.results["extra"] = "<script>bad()</script>" + "x" * 20000
        self.row.save(update_fields=["results"])
        response = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DNS checks")
        self.assertContains(response, "address_mismatch")
        self.assertNotContains(response, "<script>bad()")
        self.assertNotContains(response, "x" * 14000)

    def test_nonstaff_cannot_read_private_dns_evidence(self):
        customer_user = User.objects.create_user(email="dns-viewer@example.com")
        self.client.force_login(customer_user)
        response = self.client.get(self.path)
        self.assertIn(response.status_code, (302, 403))
        self.assertNotIn(self.account.domain, response.content.decode())

    def test_recheck_is_post_only_and_passes_the_canonical_staff_actor(self):
        url = f"/provisioning/virtualmin/accounts/{self.account.pk}/dns/recheck/"
        with patch(
            "apps.provisioning.hosted_domain_dns_views.request_recheck", return_value=Ok({"pending": True})
        ) as check:
            self.assertEqual(self.client.get(url).status_code, 405)
            check.assert_not_called()
            self.assertEqual(self.client.post(url).status_code, 302)
        self.assertEqual(check.call_args.kwargs["actor"].pk, self.staff.pk)
        self.assertEqual(check.call_args.args[0].pk, self.account.pk)

    def test_list_queries_do_not_grow_per_account(self):
        with CaptureQueriesContext(connection) as initial:
            self.assertEqual(self.client.get(self.path).status_code, 200)
        for _number in range(10):
            HostedDomainDnsStatus.objects.create(account=_distinct_account(self.server), healthy=False)
        with CaptureQueriesContext(connection) as larger:
            self.assertEqual(self.client.get(self.path).status_code, 200)
        self.assertLessEqual(len(larger), len(initial) + 2)
