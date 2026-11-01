"""The Virtualmin account, accounts and job pages use the button component and the page's CSRF token.

Their action buttons were hand-written because each carried the CSRF token in its own hx-headers, which the button
tag couldn't build. The page now gives htmx the token on <body>, so the buttons are the component (one look, one size
scale, the shared spinner) and no element repeats the token.
"""

from __future__ import annotations

from django.urls import reverse

from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture
from tests.ui.node_harness import Markup


class VirtualminPagesUseTheComponentTests(VirtualminViewsFixture):
    def pages(self) -> dict[str, str]:
        self.account.restore_hold = "pair_restore"
        self.account.restore_hold_safety_backup_id = "safety-1"
        self.account.save(update_fields=["restore_hold", "restore_hold_safety_backup_id"])
        job = VirtualminProvisioningJob.objects.create(
            server=self.server, account=self.account, operation="backup_domain", status="attention"
        )
        return {
            "account": reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]),
            "accounts": reverse("provisioning:virtualmin_accounts"),
            "job": reverse("provisioning:virtualmin_job_status", args=[job.pk]),
        }

    def test_no_control_carries_its_own_csrf_header_and_htmx_buttons_are_the_component(self) -> None:
        checked = 0
        for name, url in self.pages().items():
            with self.subTest(page=name):
                html = self.client.get(url).content.decode()
                elements = Markup(html).elements
                body = next(attrs for tag, attrs in elements if tag == "body")
                for tag, attrs in elements:
                    if tag != "body":
                        self.assertNotIn("X-CSRFToken", attrs.get("hx-headers", ""), (name, attrs))
                    if tag == "button" and attrs.get("hx-post"):
                        checked += 1
                        self.assertIn("ui-btn", attrs.get("class", ""), (name, attrs))
                self.assertIn("X-CSRFToken", body.get("hx-headers", ""))
        self.assertGreaterEqual(checked, 5)  # suspend, hold re-enable and safety restore, sync, job resolve
