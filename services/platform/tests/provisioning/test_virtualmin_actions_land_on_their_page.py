"""Virtualmin account and job actions land on the page they lead to, with the address bar following.

The account page's actions (suspend, activate, take a base or differential backup, re-enable after a hold, restore
the safety backup) and the job page's resolve/node-lost post with htmx into `body`. Their views redirect, so htmx
followed the redirect and swapped the next page into the body while the address bar stayed on the old page: a reload
or a bookmark went back. htmx requests now get HX-Redirect to that page; plain posts keep their 302.
"""

from __future__ import annotations

from django.urls import reverse

from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture


class ActionsLandOnTheirPageTests(VirtualminViewsFixture):
    def detail(self) -> str:
        return reverse("provisioning:virtualmin_account_detail", args=[self.account.pk])

    def assert_lands(self, url: str, destination_prefix: str) -> None:
        htmx = self.client.post(url, HTTP_HX_REQUEST="true", HTTP_HX_CURRENT_URL="http://testserver" + self.detail())
        self.assertEqual(htmx.status_code, 200, url)
        self.assertTrue(htmx["HX-Redirect"].startswith(destination_prefix), (url, htmx["HX-Redirect"]))
        plain = self.client.post(url, HTTP_HX_CURRENT_URL="http://testserver" + self.detail())
        self.assertEqual(plain.status_code, 302, url)

    def test_account_page_actions(self) -> None:
        detail = self.detail()
        jobs = reverse("provisioning:virtualmin_job_status", args=["00000000-0000-0000-0000-000000000000"]).rsplit(
            "00000000", 1
        )[0]
        for name in ("virtualmin_account_suspend", "virtualmin_account_activate", "virtualmin_account_hold_reenable"):
            with self.subTest(name=name):
                self.assert_lands(reverse(f"provisioning:{name}", args=[self.account.pk]), detail)
        for name in ("virtualmin_account_take_base", "virtualmin_account_take_differential"):
            with self.subTest(name=name):
                url = reverse(f"provisioning:{name}", args=[self.account.pk])
                htmx = self.client.post(url, HTTP_HX_REQUEST="true")
                self.assertEqual(htmx.status_code, 200)
                self.assertTrue(htmx["HX-Redirect"].startswith((detail, jobs)), htmx["HX-Redirect"])

    def test_job_page_actions(self) -> None:
        job = VirtualminProvisioningJob.objects.create(
            server=self.server, account=self.account, operation="backup_domain", status="failed"
        )
        status_page = reverse("provisioning:virtualmin_job_status", args=[job.pk])
        for name in ("virtualmin_job_resolve", "virtualmin_job_node_lost"):
            with self.subTest(name=name):
                url = reverse(f"provisioning:{name}", args=[job.pk])
                htmx = self.client.post(url, HTTP_HX_REQUEST="true")
                self.assertEqual(htmx.status_code, 200)
                self.assertEqual(htmx["HX-Redirect"], status_page)
                self.assertEqual(self.client.post(url).status_code, 302)
