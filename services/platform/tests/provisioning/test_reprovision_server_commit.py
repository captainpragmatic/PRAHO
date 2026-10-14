"""Reprovisioning commits ``account.server`` only after the domain exists on the target.

``reprovision_virtualmin_account`` used to save the target server on the account before
``create-domain`` ran and kept it when the create failed, so an account whose domain still
lived on the old node pointed at a node that never held it.
"""

from __future__ import annotations

from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import override_settings

from apps.common.types import Err, Ok
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class ReprovisionServerCommitTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.account.status = "active"
        self.account.save(update_fields=["status", "updated_at"])
        self.target = VirtualminServer.objects.create(
            name="vm-test-2",
            hostname="vm2.example.com",
            api_username="praho-acl",
            api_port=10000,
            status="active",
            max_domains=1000,
            current_domains=0,
        )
        self.target.set_api_password("target_password")
        self.target.save()

    def _stored_server_id(self) -> object:
        return VirtualminAccount.objects.values_list("server_id", flat=True).get(pk=self.account.pk)

    def test_a_failed_create_leaves_the_account_on_its_old_server(self) -> None:
        with patch.object(VirtualminProvisioningService, "_execute_domain_creation", return_value=Err("boom")):
            result = VirtualminProvisioningService().reprovision_virtualmin_account(self.account, self.target)

        self.assertTrue(result.is_err())
        self.assertEqual(self._stored_server_id(), self.server.pk)
        self.assertEqual(self.account.server_id, self.server.pk)  # the caller's object is not left staged
        self.assertEqual(VirtualminAccount.objects.get(pk=self.account.pk).status, "error")

    def test_a_create_that_raises_leaves_the_account_on_its_old_server(self) -> None:
        with patch.object(VirtualminProvisioningService, "_execute_domain_creation", side_effect=RuntimeError("boom")):
            result = VirtualminProvisioningService().reprovision_virtualmin_account(self.account, self.target)

        self.assertTrue(result.is_err())
        self.assertEqual(self._stored_server_id(), self.server.pk)
        self.assertEqual(self.account.server_id, self.server.pk)

    def test_the_create_runs_against_the_target_before_anything_is_stored(self) -> None:
        seen: dict[str, object] = {}

        def create(account: VirtualminAccount, job: object) -> Ok[dict[str, bool]]:
            seen["in_memory"] = account.server_id
            seen["stored"] = self._stored_server_id()
            return Ok({"created": True})

        with patch.object(VirtualminProvisioningService, "_execute_domain_creation", side_effect=create):
            result = VirtualminProvisioningService().reprovision_virtualmin_account(self.account, self.target)

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(seen["in_memory"], self.target.pk)  # the create is driven against the target
        self.assertEqual(seen["stored"], self.server.pk)  # but nothing was stored yet
        self.assertEqual(self._stored_server_id(), self.target.pk)  # committed once the create is verified

    def test_a_verified_create_commits_the_server_with_the_active_state(self) -> None:
        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("dict[str, object]", kwargs["params"])
            return http_response({"status": "success", "command": params.get("program")})

        service = VirtualminProvisioningService(self.target)
        with (
            patch.object(service, "_validate_provisioning_preconditions", return_value=Ok(True)),
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport),
        ):
            result = service.reprovision_virtualmin_account(self.account, self.target)

        self.assertTrue(result.is_ok(), result)
        stored = VirtualminAccount.objects.get(pk=self.account.pk)
        self.assertEqual((stored.server_id, stored.status), (self.target.pk, "active"))
        self.target.refresh_from_db()
        self.assertEqual(self.target.current_domains, 1)

    def test_a_rejected_create_on_the_target_leaves_the_old_server(self) -> None:
        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("dict[str, object]", kwargs["params"])
            return http_response({"status": "failure", "error": "no such template", "command": params.get("program")})

        service = VirtualminProvisioningService(self.target)
        with (
            patch.object(service, "_validate_provisioning_preconditions", return_value=Ok(True)),
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport),
        ):
            result = service.reprovision_virtualmin_account(self.account, self.target)

        self.assertTrue(result.is_err())
        self.assertEqual(self._stored_server_id(), self.server.pk)
        self.target.refresh_from_db()
        self.assertEqual(self.target.current_domains, 0)

    def test_reprovisioning_in_place_still_works(self) -> None:
        with patch.object(VirtualminProvisioningService, "_execute_domain_creation", return_value=Ok({})):
            result = VirtualminProvisioningService().reprovision_virtualmin_account(self.account)

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(self._stored_server_id(), self.server.pk)
