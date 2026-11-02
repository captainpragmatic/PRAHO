"""A destroyed deployment that had a server is re-deployed once its teardown or reconciliation proved it empty.

The proof is bound to the current attempt (``resources_proved_absent_for == correlation_id``). The earlier server's
cost window is kept as a lifetime before the row's timestamps are reset.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.infrastructure.cost_service import CostTrackingService
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment, NodeServerLifetime
from apps.infrastructure.server_lifetimes import save_legacy_window
from tests.infrastructure.test_redeploy import destroyed_row, new_size, redeploy

User = get_user_model()
STARTED = timezone.now() - timedelta(days=2)
DESTROYED = STARTED + timedelta(minutes=3)


def torn_down(**fields: Any) -> NodeDeployment:
    """Staging -001 after its proof: destroyed by a verified teardown, had a server for three minutes."""
    deployment = destroyed_row(
        server_create_state="created",
        provider_token_fingerprint=provider_token_fingerprint("tok"),
        started_at=STARTED,
        destroyed_at=DESTROYED,
    )
    values: dict[str, Any] = {"resources_proved_absent_for": deployment.correlation_id, **fields}
    NodeDeployment.objects.filter(pk=deployment.pk).update(**values)
    deployment.refresh_from_db()
    return deployment


class RedeployAfterTeardownTests(TestCase):
    def test_archival_skips_nonpositive_windows_and_does_not_duplicate_history(self) -> None:
        for delta in (timedelta(0), -timedelta(hours=1)):
            with self.subTest(delta=delta):
                deployment = torn_down(started_at=STARTED, destroyed_at=STARTED + delta)
                save_legacy_window(deployment, timezone.now(), allow_created_at_fallback=True)
                self.assertFalse(deployment.server_lifetimes.exists())
        deployment = torn_down()
        save_legacy_window(deployment, timezone.now(), allow_created_at_fallback=True)
        original = list(deployment.server_lifetimes.values())
        save_legacy_window(deployment, timezone.now(), allow_created_at_fallback=True)
        self.assertEqual(list(deployment.server_lifetimes.values()), original)

    def test_never_created_legacy_redeploy_does_not_archive_history(self) -> None:
        deployment = torn_down(server_create_state="unknown", started_at=None)
        NodeDeployment.objects.filter(pk=deployment.pk).update(reconciliation_record={
            "never_created_attested": True, "correlation_id": str(deployment.correlation_id),
        })
        deployment.refresh_from_db()
        self.assertTrue(deployment.never_got_a_server)
        result, _gateway = redeploy(deployment, new_size(deployment, "cpx22"))
        self.assertTrue(result.is_ok(), result)
        self.assertFalse(deployment.server_lifetimes.filter(legacy=True).exists())

    def test_archive_and_redeploy_reset_roll_back_together(self) -> None:
        from apps.infrastructure.deployment_lifecycle import owned_update  # noqa: PLC0415

        deployment = torn_down(server_create_state="unknown", started_at=None,
                              created_at=STARTED - timedelta(days=1))
        original_attempt = deployment.correlation_id

        def fail_reset(*args: Any, **kwargs: Any) -> None:
            if "correlation_id" in kwargs:
                self.assertTrue(deployment.server_lifetimes.filter(legacy=True).exists())
                raise RuntimeError("reset failed after archival")
            owned_update(*args, **kwargs)

        with (
            patch("apps.infrastructure.deployment_service.owned_update", side_effect=fail_reset),
            self.assertRaisesMessage(RuntimeError, "reset failed after archival"),
        ):
            redeploy(deployment, new_size(deployment, "cpx22"))
        deployment.refresh_from_db()
        self.assertEqual((deployment.status, deployment.correlation_id), ("destroyed", original_attempt))
        self.assertFalse(deployment.server_lifetimes.exists())

    def test_unknown_legacy_redeploy_preserves_historical_cost(self) -> None:
        start = timezone.now() - timedelta(days=4)
        end = start + timedelta(hours=24)
        deployment = torn_down(server_create_state="unknown", started_at=None, created_at=start, destroyed_at=end)
        old_attempt, old_size = deployment.correlation_id, deployment.node_size
        self.assertFalse(deployment.never_got_a_server)
        self.assertFalse(deployment.server_lifetimes.exists())
        costs = CostTrackingService()
        before = costs.calculate_deployment_costs(deployment, start, end).unwrap().cost_eur
        expected = (old_size.monthly_cost_eur / Decimal(730) * 24).quantize(Decimal("0.0001"))
        self.assertEqual(before.quantize(Decimal("0.0001")), expected)
        result, _gateway = redeploy(deployment, new_size(deployment, "cpx22"))
        self.assertTrue(result.is_ok(), result)
        after = costs.calculate_deployment_costs(deployment, start, end)
        self.assertTrue(after.is_ok(), "redeploy lost the historical billable window")
        self.assertEqual(after.unwrap().cost_eur.quantize(Decimal("0.0001")), expected)
        old = deployment.server_lifetimes.get(legacy=True)
        self.assertEqual((old.started_at, old.ended_at, old.correlation_id, old.node_size_id),
                         (start, end, old_attempt, old_size.pk))
        self.assertNotEqual(deployment.correlation_id, old_attempt)

    def test_a_row_proved_empty_is_re_deployed_and_keeps_its_first_server_window(self) -> None:
        deployment = torn_down()
        old_size = deployment.node_size
        result, gateway = redeploy(deployment, new_size(deployment, "cpx22"))
        self.assertTrue(result.is_ok(), result)
        gateway.create_server.assert_called_once()
        first = NodeServerLifetime.objects.filter(deployment=deployment, legacy=True).first()
        assert first is not None, "the first server's window was lost"
        self.assertEqual((first.started_at, first.ended_at, first.node_size_id), (STARTED, DESTROYED, old_size.pk))
        self.assertIsNone(deployment.resources_proved_absent_for)
        self.assertTrue(
            NodeServerLifetime.objects.filter(deployment=deployment, legacy=False, ended_at__isnull=True).exists()
        )

    def test_each_missing_proof_refuses(self) -> None:
        cases: dict[str, dict[str, Any]] = {
            "no proof": {"resources_proved_absent_for": None},
            "proof for an earlier attempt": {"resources_proved_absent_for": uuid.uuid4()},
            "flagged": {"needs_reconciliation": True},
            "server id": {"external_node_id": "srv-1"},
        }
        for name, fields in cases.items():
            with self.subTest(name):
                deployment = torn_down(**fields)
                result, gateway = redeploy(deployment, new_size(deployment, f"cpx{len(name)}"))
                self.assertTrue(result.is_err(), name)
                gateway.create_server.assert_not_called()

    def test_an_open_lifetime_refuses(self) -> None:
        deployment = torn_down()
        NodeServerLifetime.objects.create(
            deployment=deployment, correlation_id=deployment.correlation_id, server_id="srv-1", node_size=deployment.node_size, monthly_cost_eur=3,
            started_at=STARTED,
        )
        result, gateway = redeploy(deployment, new_size(deployment, "cpx22"))
        self.assertTrue(result.is_err())
        gateway.create_server.assert_not_called()

    def test_the_deployment_page_offers_re_deploy_for_a_row_proved_empty(self) -> None:
        deployment = torn_down()
        self.client.force_login(User.objects.create_superuser(email="rd-proof@example.com", password="x"))
        response: Any = self.client.get(reverse("infrastructure:deployment_detail", args=[deployment.pk]))
        self.assertTrue(response.context["can_redeploy"])
