"""The Virtualmin restore page renders.

Its template could not compile: the first line had the old page header pasted into the middle
of `{% extends "base.html" %}`, and the breadcrumb call passed `steps=` instead of the items the
tag requires. Every GET with a backup to restore from raised instead of showing the form.
"""

from __future__ import annotations

import re
from unittest.mock import patch

from django.urls import reverse

from apps.common.types import Ok
from tests.factories.core_factories import create_admin_user
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase

_BACKUP = {"backup_id": "bk-1", "backup_type": "full", "created_at": "2026-10-01 10:00", "size_mb": 12}


class VirtualminRestorePageTests(VirtualminTaskTestBase):
    def test_the_restore_form_renders_with_its_breadcrumb(self) -> None:
        self.client.force_login(create_admin_user())
        with patch(
            "apps.provisioning.virtualmin_views.VirtualminBackupService.list_backups", return_value=Ok([_BACKUP])
        ):
            response = self.client.get(reverse("provisioning:virtualmin_account_restore", args=[self.account.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'value="bk-1"')
        nav = re.search(r'<nav aria-label="Breadcrumb".*?</nav>', response.content.decode(), re.S)
        assert nav is not None, "the restore page renders no breadcrumb"
        for url in (
            reverse("provisioning:virtualmin_accounts"),
            reverse("provisioning:virtualmin_account_detail", args=[self.account.id]),
        ):
            self.assertIn(f'href="{url}"', nav.group(0))
        self.assertIn("Restore", nav.group(0))
