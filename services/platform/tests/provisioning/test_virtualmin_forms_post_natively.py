"""The Virtualmin server and restore forms post as normal forms, and Test Connection works more than once.

Both forms posted with htmx into a container inside themselves (outerHTML, no hx-select). Their views answer with
full pages: a redirect on success, the whole page again on a validation error. So a full copy of the page, nav and
all, appeared inside the form, and the address bar never moved. A native post shows those pages as pages.

Test Connection sits inside the server form and inherited its outerHTML swap. The result it swapped in has no id, so
the first result replaced #connection-test-result and every later click had no target.
"""

from __future__ import annotations

from unittest.mock import patch

from django.urls import reverse

from apps.common.types import Ok
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture
from tests.ui.node_harness import Markup


class VirtualminFormsTests(VirtualminViewsFixture):
    def forms(self, url: str) -> list[dict[str, str]]:
        page = Markup(self.client.get(url).content.decode())
        return [attrs for tag, attrs in page.elements if tag == "form" and attrs.get("method") == "post"]

    @patch.object(
        VirtualminBackupService,
        "list_backups",
        return_value=Ok([{"backup_id": "bk-1", "backup_type": "full", "created_at": "2026-10-31"}]),
    )
    def test_the_server_and_restore_forms_post_natively(self, _listing: object) -> None:
        for url in (
            reverse("provisioning:virtualmin_server_edit", args=[self.server.pk]),
            reverse("provisioning:virtualmin_account_restore", args=[self.account.pk]),
        ):
            with self.subTest(url=url):
                forms = [f for f in self.forms(url) if "csrfmiddlewaretoken" not in f]
                self.assertTrue(forms)
                for form in forms:
                    self.assertNotIn("hx-post", form)
                    self.assertNotIn("hx-target", form)

    def test_test_connection_swaps_inside_its_result_box(self) -> None:
        page = Markup(
            self.client.get(reverse("provisioning:virtualmin_server_edit", args=[self.server.pk])).content.decode()
        )
        buttons = [
            attrs
            for tag, attrs in page.elements
            if tag == "button" and attrs.get("hx-target") == "#connection-test-result"
        ]
        self.assertEqual(len(buttons), 1)
        self.assertEqual(buttons[0].get("hx-swap"), "innerHTML")
