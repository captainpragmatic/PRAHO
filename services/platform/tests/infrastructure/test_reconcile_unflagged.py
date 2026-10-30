"""Unflagged failed or destroyed rows can be reconciled to prove, or attest, that nothing they owned remains.

(a) A never-created attestation for a row whose create outcome is unknown (staging -002). (b) A search that proves
absence for a destroyed row (staging -001, torn down before the proof was recorded). Both record the proof for the
current attempt, which re-deploy needs.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.test import TestCase
from django.utils import timezone

from apps.common.types import Ok
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment, NodeServerLifetime
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.infrastructure.test_node_teardown import Harness as TeardownHarness
from tests.infrastructure.test_reconcile_deployment import TOKEN, Harness
from tests.infrastructure.test_reconcile_deployment import legacy_row as flagged_legacy_row

LONG_AGO = timezone.now() - timedelta(days=1)


def row(status: str, **fields: Any) -> NodeDeployment:
    deployment = _create_deployment(status)
    values: dict[str, Any] = {"needs_reconciliation": False, "ipv4_address": None, "updated_at": LONG_AGO, **fields}
    NodeDeployment.objects.filter(pk=deployment.pk).update(**values)
    deployment.refresh_from_db()
    return deployment


def staging_002() -> NodeDeployment:
    """Destroyed, create outcome unknown, unflagged, no token recorded, nothing reconciled."""
    return row("destroyed", server_create_state="unknown", provider_token_fingerprint="", destroyed_at=LONG_AGO)


def staging_001() -> NodeDeployment:
    """Destroyed by a teardown before proofs were recorded; had a server; token recorded."""
    return row(
        "destroyed",
        server_create_state="created",
        provider_token_fingerprint=provider_token_fingerprint(TOKEN),
        started_at=LONG_AGO - timedelta(minutes=3),
        destroyed_at=LONG_AGO,
    )


class NeverCreatedAttestationTests(TestCase):
    def test_the_002_shape_is_attested_and_can_be_re_deployed(self) -> None:
        h = Harness()
        deployment = staging_002()
        result = h.run(deployment, attest_never_created=True, attest_no_resources=True)
        self.assertTrue(result.is_ok(), result)
        settled = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertEqual((settled.status, settled.destroyed_at), ("destroyed", deployment.destroyed_at))
        self.assertTrue(settled.never_got_a_server)
        self.assertEqual(settled.resources_proved_absent_for, deployment.correlation_id)
        self.assertIsNone(settled.operation_token)
        h.cloud.find_servers_by_label.assert_called_once()

    def test_an_unflagged_failed_row_is_attested_and_settled_destroyed(self) -> None:
        h = Harness()
        deployment = row("failed", server_create_state="unknown", provider_token_fingerprint="")
        self.assertTrue(h.run(deployment, attest_never_created=True, attest_no_resources=True).is_ok())
        settled = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertEqual(settled.status, "destroyed")
        self.assertTrue(settled.never_got_a_server)

    def test_the_attestation_deletes_unconfirmed_lifetimes(self) -> None:
        h = Harness()
        deployment = staging_002()
        NodeServerLifetime.objects.create(
            deployment=deployment, server_id="", node_size=deployment.node_size, monthly_cost_eur=3,
            started_at=LONG_AGO,
        )
        self.assertTrue(h.run(deployment, attest_never_created=True, attest_no_resources=True).is_ok())
        self.assertFalse(NodeServerLifetime.objects.filter(deployment=deployment).exists())


class AbsenceProofTests(TestCase):
    def test_the_001_shape_is_proved_absent_by_a_search(self) -> None:
        h = Harness()
        deployment = staging_001()
        result = h.run(deployment, evidence="")
        self.assertTrue(result.is_ok(), result)
        settled = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertEqual(settled.status, "destroyed")
        self.assertEqual(settled.resources_proved_absent_for, deployment.correlation_id)
        self.assertEqual(settled.reconciliation_record["provenance"], "matched")
        self.assertFalse(settled.never_got_a_server)

    def test_the_proof_closes_open_lifetimes(self) -> None:
        h = Harness()
        deployment = staging_001()
        NodeServerLifetime.objects.create(
            deployment=deployment, server_id="srv-1", node_size=deployment.node_size, monthly_cost_eur=3,
            started_at=LONG_AGO,
        )
        self.assertTrue(h.run(deployment, evidence="").is_ok())
        self.assertFalse(NodeServerLifetime.objects.filter(deployment=deployment, ended_at__isnull=True).exists())


class UnflaggedRefusalTests(TestCase):
    def test_each_unsafe_unflagged_row_is_refused_with_nothing_written(self) -> None:
        cases: dict[str, tuple[NodeDeployment, dict[str, Any]]] = {
            "failed without the attestation": (
                row("failed", server_create_state="unknown", provider_token_fingerprint=provider_token_fingerprint(TOKEN)),
                {"evidence": ""},
            ),
            "dns ids": (
                row("destroyed", server_create_state="unknown", dns_record_ids=[{"zone_id": "z1", "name": "n"}]),
                {"attest_never_created": True, "attest_no_resources": True},
            ),
            "server id": (row("destroyed", server_create_state="unknown", external_node_id="srv-9"),
                          {"attest_never_created": True, "attest_no_resources": True}),
            "created is not never-created": (
                row("destroyed", server_create_state="created"),
                {"attest_never_created": True, "attest_no_resources": True},
            ),
            "completed": (row("completed", server_create_state="created", provider_token_fingerprint=provider_token_fingerprint(TOKEN)), {"evidence": ""}),
        }
        for name, (deployment, options) in cases.items():
            with self.subTest(name):
                h = Harness()
                before = NodeDeployment.objects.get(pk=deployment.pk)
                self.assertTrue(h.run(deployment, **options).is_err(), name)
                after = NodeDeployment.objects.get(pk=deployment.pk)
                self.assertEqual(
                    (after.status, after.resources_proved_absent_for, after.reconciliation_record),
                    (before.status, None, before.reconciliation_record),
                )

    def test_a_find_refuses_an_unflagged_row(self) -> None:
        h = Harness()
        deployment = staging_001()
        h.cloud.find_servers_by_name.return_value = Ok(["srv-7"])
        self.assertTrue(h.run(deployment, evidence="").is_err())
        self.assertIsNone(NodeDeployment.objects.get(pk=deployment.pk).resources_proved_absent_for)

    def test_a_flagged_row_still_settles_as_before(self) -> None:
        h = Harness()
        deployment = flagged_legacy_row()
        self.assertTrue(h.run(deployment, attest_no_resources=True).is_ok())
        self.assertEqual(NodeDeployment.objects.get(pk=deployment.pk).resources_proved_absent_for,
                         deployment.correlation_id)


class TeardownProofTests(TestCase):
    def test_a_teardown_under_the_recorded_token_proves_absence(self) -> None:
        h = TeardownHarness()
        self.assertTrue(h.destroy().is_ok())
        self.assertEqual(h.row().resources_proved_absent_for, h.deployment.correlation_id)

    def test_a_teardown_without_a_recorded_token_proves_nothing(self) -> None:
        h = TeardownHarness(fingerprint="")
        self.assertTrue(h.destroy().is_ok())
        row_after = h.row()
        self.assertEqual(row_after.status, "destroyed")
        self.assertIsNone(row_after.resources_proved_absent_for)
