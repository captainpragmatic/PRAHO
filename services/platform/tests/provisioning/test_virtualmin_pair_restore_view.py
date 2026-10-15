"""The staff "Restore pair" page: it says plainly what a pair restore does, and queues one."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.urls import reverse

from apps.common.types import Ok
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.settings.services import SettingsService
from apps.users.models import User
from tests.provisioning.test_virtualmin_pair_restore import PairRestoreCase


class RestorePairViewTests(PairRestoreCase):
    def setUp(self) -> None:
        super().setUp()
        self.staff = User.objects.create_user(email="pair-view@example.com", password="pair-view-password", staff_role="admin")
        self.client.force_login(self.staff)
        self.url = reverse("provisioning:virtualmin_account_restore_pair", args=[self.account.pk])
        listing: list[dict[str, Any]] = [{**self.base, "created_at": "2026-10-01T00:00:00"}, {**self.diff, "created_at": "2026-10-02T00:00:00"}]
        patcher = patch.object(VirtualminBackupService, "list_backups", return_value=Ok(listing))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_page_states_the_two_facts_an_operator_must_know(self) -> None:
        page = self.client.get(self.url).content.decode()
        self.assertIn("Files deleted after the base was taken will reappear", page)
        self.assertIn("databases come from the differential", page)
        self.assertIn("diff-1", page)

    def test_confirming_queues_a_pair_restore_job(self) -> None:
        response = self.client.post(self.url, {"differential_id": "diff-1", "confirm_restore": "on"})
        self.assertEqual(response.status_code, 302)
        job = VirtualminProvisioningJob.objects.get(operation="restore_domain")
        self.assertEqual(
            (job.parameters["restore_mode"], job.parameters["base_backup_id"], job.parameters["differential_backup_id"]),
            ("pair", "base-1", "diff-1"),
        )
        self.assertEqual(job.parameters["initiated_by"], "staff:pair-view@example.com")

    def test_without_the_confirmation_nothing_is_queued(self) -> None:
        self.client.post(self.url, {"differential_id": "diff-1"})
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_with_the_flag_off_the_page_queues_nothing_and_the_account_page_hides_the_link(self) -> None:
        SettingsService.update_setting("provisioning.incremental_backups_enabled", False)
        response = self.client.post(self.url, {"differential_id": "diff-1", "confirm_restore": "on"}, follow=True)
        self.assertContains(response, "Differential backups are not enabled")
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        self.assertRedirects(
            self.client.get(self.url),
            reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]),
        )
        detail = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]))
        self.assertNotContains(detail, self.url)

    def test_the_account_page_links_to_it(self) -> None:
        page = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk])).content.decode()
        self.assertIn(self.url, page)
