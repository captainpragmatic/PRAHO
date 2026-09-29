"""A failed cosmetic refresh must not undo a committed node activation.

`NodeRegistrationService.verify_and_activate` ends with a `refresh_from_db()` the code itself calls
cosmetic: the CAS update has already committed, so the node IS active regardless. That refresh was
suppressed with `contextlib.suppress(Exception)`, then narrowed to `DatabaseError` — and the narrowing
was wrong, because Django follows PEP 249 where `Error` has exactly two direct subclasses,
`InterfaceError` and `DatabaseError`. A dropped connection therefore escaped and turned a successful
activation into a raised exception, which is precisely what the comment beside it promises cannot
happen. `apps/billing/refund_service.py` names the pair in five places; this site did not.

These are also the first tests `verify_and_activate` has had at all, which matters on its own: the
method decides whether a provisioning node starts receiving customer domains.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from django.db import InterfaceError
from django.test import TestCase

from apps.common.types import Ok
from apps.infrastructure.registration_service import NodeRegistrationService
from apps.provisioning.virtualmin_models import VirtualminServer


class VerifyAndActivateRefreshTests(TestCase):
    def setUp(self) -> None:
        self.server = VirtualminServer.objects.create(
            name="vm-activate-1",
            hostname="vm-activate-1.example.test",
            api_username="praho-acl",
            api_port=10000,
            status="disabled",
            max_domains=100,
            current_domains=0,
        )

    def _healthy_node(self) -> tuple[Any, Any, Any, Any]:
        """The four seams  reaches through, all function-level imports (ADR-0007)."""
        vault = MagicMock()
        vault.get_credential.return_value = Ok(("praho-acl", "s3cret", {}))
        gateway = MagicMock()
        gateway.test_connection.return_value = Ok({"healthy": True})
        return (
            patch("apps.common.credential_vault.get_credential_vault", return_value=vault),
            patch("apps.provisioning.virtualmin_gateway.get_virtualmin_config", return_value={"timeout": 30}),
            patch("apps.provisioning.virtualmin_gateway.VirtualminConfig.from_credentials", return_value=MagicMock()),
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway", return_value=gateway),
        )

    def test_a_healthy_node_activates(self) -> None:
        """The positive control: without it, the test below could pass by never activating at all."""
        a, b, c, d = self._healthy_node()
        with a, b, c, d:
            result = NodeRegistrationService().verify_and_activate(self.server)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "active")

    def test_a_dropped_connection_during_the_final_refresh_does_not_undo_activation(self) -> None:
        """Revert the `InterfaceError` in the suppress and this raises instead of returning Ok."""
        a, b, c, d = self._healthy_node()
        with a, b, c, d, patch.object(
            VirtualminServer, "refresh_from_db", side_effect=InterfaceError("connection already closed")
        ):
            result = NodeRegistrationService().verify_and_activate(self.server)

        self.assertTrue(result.is_ok(), "a cosmetic refresh failure must not fail the activation")
        # The row really is active: the CAS update committed before the refresh was attempted.
        self.assertEqual(
            VirtualminServer.objects.values_list("status", flat=True).get(pk=self.server.pk), "active"
        )
