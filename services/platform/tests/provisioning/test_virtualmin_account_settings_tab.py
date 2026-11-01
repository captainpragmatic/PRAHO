"""The Virtualmin account's Settings tab shows what Platform stores, read-only.

It had Save and Cancel buttons with no form or route behind them, inputs with no name, a contact email and a disk
quota read from attributes the model doesn't have (always blank), hard-coded PHP versions, and bandwidth in MB under
a GB label. Editing can come later as a real feature (quotas from the plan are #776); until then it shows facts.
"""

from __future__ import annotations

from django.urls import reverse

from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture


class AccountSettingsTabTests(VirtualminViewsFixture):
    def settings_tab(self) -> str:
        html = self.client.get(
            reverse("provisioning:virtualmin_account_detail", args=[self.account.pk])
        ).content.decode()
        start = html.index("<!-- Settings Tab -->")
        return html[start : html.index("<script", start)]  # the tab is the last thing before the page's script

    def test_it_has_no_controls_that_do_nothing(self) -> None:
        tab = self.settings_tab()
        for control in ("<input", "<select", "Save Changes", "PHP 8.1"):
            self.assertNotIn(control, tab)

    def test_it_shows_the_stored_quotas_in_the_units_it_names(self) -> None:
        self.account.template_name = "Business"
        self.account.disk_quota_mb = 10240
        self.account.bandwidth_quota_mb = -1
        self.account.save(update_fields=["template_name", "disk_quota_mb", "bandwidth_quota_mb"])
        tab = self.settings_tab()
        self.assertIn("Business", tab)
        self.assertIn("10 GB", tab)
        self.assertIn("Unlimited", tab)

        self.account.disk_quota_mb = None
        self.account.bandwidth_quota_mb = 51200
        self.account.save(update_fields=["disk_quota_mb", "bandwidth_quota_mb"])
        tab = self.settings_tab()
        self.assertIn("Not set", tab)
        self.assertIn("50 GB", tab)
