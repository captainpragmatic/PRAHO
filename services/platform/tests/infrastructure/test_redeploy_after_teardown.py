"""A destroyed deployment that had a server is re-deployed once its teardown or reconciliation proved it empty.

The proof is bound to the current attempt (``resources_proved_absent_for == correlation_id``). The earlier server's
cost window is kept as a lifetime before the row's timestamps are reset.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment, NodeServerLifetime
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
