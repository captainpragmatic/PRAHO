"""Writers of an account's usage, domains or protection never write back stale chain fields.

The differential chain state (chain_base, its fingerprint, the epoch) is owned by the chain
transitions, which hold the row lock. A writer that loaded the account earlier and then saves
every column would undo an invalidation that committed in between, silently reviving a dead
chain. Each save below runs while a chain transition commits between the load and the write.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

from django.core.management import call_command
from django.db import models
from django.urls import reverse

from apps.common.types import Ok
from apps.provisioning.virtualmin_gateway import VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminAccount
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture

CONCURRENT_EPOCHS = 5


class PartialSaveTests(VirtualminViewsFixture):
    def setUp(self) -> None:
        super().setUp()
        VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_epoch=2)

    def concurrent_invalidation(self) -> Callable[..., Any]:
        """Save wrapper: a chain transition commits just before each save of THIS account."""
        real_save = VirtualminAccount.save

        def save(instance: VirtualminAccount, *args: Any, **kwargs: Any) -> Any:
            if instance.pk == self.account.pk:
                VirtualminAccount.objects.filter(pk=instance.pk).update(
                    chain_epoch=models.F("chain_epoch") + CONCURRENT_EPOCHS, chain_base_fingerprint=""
                )
            return real_save(instance, *args, **kwargs)

        return save

    def assert_chain_untouched(self) -> None:
        self.account.refresh_from_db()
        self.assertEqual(self.account.chain_epoch, 2 + CONCURRENT_EPOCHS, "a stale save overwrote the chain epoch")

    def test_the_usage_sync_command_keeps_the_chain_epoch(self) -> None:
        usage = Ok({"disk_usage_mb": 77, "bandwidth_usage_mb": 88})
        with (
            patch.object(VirtualminGateway, "get_domain_info", return_value=usage),
            patch.object(VirtualminAccount, "save", autospec=True, side_effect=self.concurrent_invalidation()),
        ):
            call_command("sync_virtualmin_usage", "--server", self.server.name, stdout=io.StringIO(), no_color=True)
        self.assert_chain_untouched()
        self.assertEqual(self.account.current_disk_usage_mb, 77)
        self.assertIsNotNone(self.account.last_sync_at)

    def test_the_staff_account_sync_keeps_the_chain_epoch(self) -> None:
        self.payload["data"] = [
            {"name": self.account.domain, "values": {"Username": [self.account.virtualmin_username], "Status": ["Enabled"]}}
        ]
        usage = Ok({"disk_usage_mb": 12, "bandwidth_usage_mb": 13})
        with (
            patch.object(VirtualminGateway, "get_domain_info", return_value=usage),
            patch.object(VirtualminAccount, "save", autospec=True, side_effect=self.concurrent_invalidation()),
        ):
            self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
        self.assert_chain_untouched()
        self.assertEqual(self.account.current_disk_usage_mb, 12)
        self.assertIsNotNone(self.account.last_sync_at)

    def test_the_protection_toggle_keeps_the_chain_epoch(self) -> None:
        before = self.account.protected_from_deletion
        with patch.object(VirtualminAccount, "save", autospec=True, side_effect=self.concurrent_invalidation()):
            self.client.post(reverse("provisioning:virtualmin_account_toggle_protection", args=[self.account.pk]))
        self.assert_chain_untouched()
        self.assertEqual(self.account.protected_from_deletion, not before)
