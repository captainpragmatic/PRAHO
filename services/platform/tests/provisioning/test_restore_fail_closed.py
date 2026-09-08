"""Restore fails closed at every gate: authorization, ownership, force, ambiguity.

The transport-based restore (#431) replaced the stubbed component machinery.
These tests pin the real gates: a backup restores only onto its own account,
force can never override foreign or unverifiable ownership, a live domain
gets a safety backup before any destructive dispatch, and ambiguous remote
outcomes surface as UNKNOWN-retriability errors (parked for attention at the
job layer) with the pushed archive retained for reconciliation.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Err, Ok, Retriability, retriability_of
from apps.provisioning.virtualmin_backup_service import RestoreConfig, VirtualminBackupService
from apps.provisioning.virtualmin_gateway import VirtualminResponse


def _listing_row(domain: str, username: str, enabled: bool | None) -> dict[str, Any]:
    return {"domain": domain, "username": username, "enabled": enabled, "attributes": {}}


def _restore_response(*, success: bool, raw: str) -> Ok[VirtualminResponse]:
    return Ok(
        VirtualminResponse(
            success=success,
            data={"status": "success"} if success else {"error": "guesswork"},
            raw_response=raw,
            http_status=200,
            execution_time=0.1,
            program="restore-domain",
            server_hostname="vm.example.com",
        )
    )


class RestoreFailClosedTests(TestCase):
    """The real restore workflow refuses everything it cannot prove safe."""

    def setUp(self) -> None:
        self.server = MagicMock()
        self.server.hostname = "vm.example.com"
        self.service = VirtualminBackupService(self.server)
        self.account = MagicMock()
        self.account.domain = "example.com"
        self.account.service_id = 42
        self.account.virtualmin_username = "owner"
        self.config = RestoreConfig(backup_id="bk-1")
        self.metadata = {
            "archive_name": "virtualmin_backup_" + "a" * 32 + ".tar.gz",
            "checksum_sha256": "b" * 64,
            "praho_service_id": "42",
            "domain": "example.com",
        }
        download_patch = patch.object(
            self.service, "_download_backup_to_spool", return_value=Ok(("/spool/x.tar.gz", self.metadata))
        )
        download_patch.start()
        self.addCleanup(download_patch.stop)
        release_patch = patch("apps.provisioning.spool.release_spool_reservation")
        release_patch.start()
        self.addCleanup(release_patch.stop)
        self.gateway = MagicMock()
        gateway_patch = patch(
            "apps.provisioning.virtualmin_backup_service.VirtualminGateway", return_value=self.gateway
        )
        gateway_patch.start()
        self.addCleanup(gateway_patch.stop)
        self.listing = patch(
            "apps.provisioning.virtualmin_migration_service.list_migration_domains",
            return_value=Ok([]),
        )
        self.listing_mock = self.listing.start()
        self.addCleanup(self.listing.stop)
        self.push_patch = patch.object(self.service, "_push_archive_to_target", return_value=Ok(None))
        self.push = self.push_patch.start()
        self.addCleanup(self.push_patch.stop)
        self.cleanup_patch = patch.object(self.service, "_cleanup_remote_archive")
        self.remote_cleanup = self.cleanup_patch.start()
        self.addCleanup(self.cleanup_patch.stop)
        self.gateway.call.return_value = _restore_response(
            success=True, raw=json.dumps({"status": "success"})
        )

    def test_wrong_service_authorization_is_refused(self) -> None:
        self.metadata["praho_service_id"] = "999"
        result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIn("does not belong", result.unwrap_err())
        self.push.assert_not_called()

    def test_wrong_domain_binding_is_refused(self) -> None:
        self.metadata["domain"] = "other.com"
        result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIn("does not match", result.unwrap_err())
        self.push.assert_not_called()

    def test_foreign_owner_refused_regardless_of_force(self) -> None:
        self.listing_mock.return_value = Ok([_listing_row("example.com", "intruder", True)])
        self.config.force_restore = True
        result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIn("foreign ownership", result.unwrap_err())
        self.push.assert_not_called()

    def test_unverifiable_state_refused_regardless_of_force(self) -> None:
        self.listing_mock.return_value = Ok([_listing_row("example.com", "owner", None)])
        self.config.force_restore = True
        result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIn("unverifiable", result.unwrap_err())
        self.push.assert_not_called()

    def test_live_domain_requires_force(self) -> None:
        self.listing_mock.return_value = Ok([_listing_row("example.com", "owner", True)])
        result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIn("force restore", result.unwrap_err())
        self.push.assert_not_called()

    def test_forced_restore_takes_safety_backup_first_and_aborts_on_its_failure(self) -> None:
        self.listing_mock.return_value = Ok([_listing_row("example.com", "owner", True)])
        self.config.force_restore = True
        with patch.object(
            VirtualminBackupService, "backup_domain", return_value=Err("no space")
        ) as safety:
            result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIn("safety backup failed", result.unwrap_err())
        safety.assert_called_once()
        self.push.assert_not_called()

    def test_safety_backup_id_is_persisted_before_destructive_dispatch(self) -> None:
        self.listing_mock.return_value = Ok([_listing_row("example.com", "owner", True)])
        self.config.force_restore = True
        notes: list[dict[str, Any]] = []
        order: list[str] = []
        self.push.side_effect = lambda *a, **k: order.append("push") or Ok(None)
        with patch.object(
            VirtualminBackupService,
            "backup_domain",
            return_value=Ok({"backup_id": "safety-1"}),
        ):
            result = self.service.restore_domain(
                account=self.account,
                config=self.config,
                note_sink=lambda note: (notes.append(note), order.append("note"))[0],
            )
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(notes, [{"safety_backup_id": "safety-1"}])
        self.assertEqual(order, ["note", "push"])
        self.assertEqual(result.unwrap()["safety_backup_id"], "safety-1")

    def test_ambiguous_restore_is_unknown_retriability_and_retains_archive(self) -> None:
        self.gateway.call.return_value = _restore_response(success=False, raw="")
        result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIs(retriability_of(result), Retriability.UNKNOWN)
        # Uncertain outcome: the pushed archive stays for reconciliation.
        self.remote_cleanup.assert_not_called()

    def test_explicit_rejection_is_definite_and_cleans_the_pushed_archive(self) -> None:
        raw = json.dumps({"status": "error", "error": "disk full"})
        self.gateway.call.return_value = _restore_response(success=False, raw=raw)
        result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIn("disk full", result.unwrap_err())
        self.assertIs(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.remote_cleanup.assert_called_once()

    def test_unverified_restore_surfaces_as_uncertain(self) -> None:
        # restore-domain succeeds but the domain never shows on the listing.
        calls = {"n": 0}

        def listing_side_effect(gateway: Any, **kwargs: Any) -> Any:
            calls["n"] += 1
            return Ok([])

        self.listing_mock.side_effect = listing_side_effect
        result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIn("could not be verified", result.unwrap_err())
        self.assertIs(retriability_of(result), Retriability.UNKNOWN)
        self.remote_cleanup.assert_not_called()

    def test_deterministic_refusals_are_not_retriable(self) -> None:
        """C1: a fail-closed refusal must be NOT_RETRIABLE, not UNKNOWN (which would park attention)."""
        self.listing_mock.return_value = Ok([_listing_row("example.com", "owner", True)])
        result = self.service.restore_domain(account=self.account, config=self.config)  # force not set
        self.assertTrue(result.is_err())
        self.assertIs(retriability_of(result), Retriability.NOT_RETRIABLE)

    def test_appeared_domain_during_transfer_is_refused(self) -> None:
        """W1: a domain absent at gate-1 but present at the re-gate has no safety backup — refuse."""
        gate_calls = {"n": 0}

        def listing_side_effect(gateway, **kwargs):
            gate_calls["n"] += 1
            # gate-1 sees nothing; the re-gate (after push) sees a live owned domain.
            return Ok([]) if gate_calls["n"] == 1 else Ok([_listing_row("example.com", "owner", True)])

        self.listing_mock.side_effect = listing_side_effect
        self.config.force_restore = True
        result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIn("appeared during the transfer", result.unwrap_err())
        # Nothing destructive ran, so the pushed archive is cleaned (determinate).
        self.remote_cleanup.assert_called_once()

    def test_component_selective_restore_is_refused_honestly(self) -> None:
        self.config.restore_email = False
        result = self.service.restore_domain(account=self.account, config=self.config)
        self.assertTrue(result.is_err())
        self.assertIn("all components", result.unwrap_err())
