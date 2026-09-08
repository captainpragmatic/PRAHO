"""Round 1b migration contracts: orchestration, transport, consumers, and staff UI."""

from __future__ import annotations

import json
import subprocess
import tempfile
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import requests
from django.db import transaction
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.types import Err, Ok, Retriability
from apps.infrastructure.ansible_service import AnsibleResult, AnsibleService
from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeRegion, NodeSize, PanelType
from apps.provisioning import virtualmin_tasks
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_gateway import VirtualminAPIError, VirtualminGateway
from apps.provisioning.virtualmin_migration_models import VirtualminMigration, account_has_active_migration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService, resume_migration
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.users.models import User
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning import test_virtualmin_tasks as task_tests


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"retry": 14400, "orm": "default"},
)
class MigrationTestBase(task_tests.VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        # fsm-bypass: establish the existing active account fixture.
        VirtualminAccount.objects.filter(pk=self.account.pk).update(
            status="active", domains=[self.account.domain]
        )
        self.account.refresh_from_db()
        VirtualminServer.objects.filter(pk=self.server.pk).update(last_health_check=timezone.now())
        self.server.refresh_from_db()
        self.target = VirtualminServer.objects.create(
            name="migration-target",
            hostname="migration-target.example.com",
            api_username="praho-acl",
            last_health_check=timezone.now(),
            current_domains=0,
        )
        self.target.set_api_password("target-test-password")
        self.target.save()
        provider = CloudProvider.objects.create(
            name="Migration provider", provider_type="hetzner", code="het",
            credential_identifier="migration-test",
        )
        region = NodeRegion.objects.create(
            provider=provider, name="Falkenstein", provider_region_id="fsn1",
            normalized_code="fsn1", country_code="de", city="Falkenstein",
        )
        size = NodeSize.objects.create(
            provider=provider, name="Migration small", display_name="Small",
            provider_type_id="cpx21", vcpus=2, memory_gb=4, disk_gb=40,
            hourly_cost_eur="0.01", monthly_cost_eur="5.00",
        )
        panel = PanelType.objects.create(
            name="Migration Virtualmin", panel_type="virtualmin", ansible_playbook="virtualmin.yml"
        )
        for number, server in enumerate((self.server, self.target), start=1):
            NodeDeployment.objects.create(
                provider=provider, node_size=size, region=region, panel_type=panel,
                hostname=f"prd-sha-het-de-fsn1-{number:03}",
                node_number=number, ipv4_address=f"203.0.113.{number}",
                virtualmin_server=server,
            )
        self.staff = User.objects.create_user(
            email="migration-staff@example.com", password="staff-test-password", staff_role="admin"
        )
        self.spool = tempfile.TemporaryDirectory()
        self.addCleanup(self.spool.cleanup)
        self.settings_values: dict[str, Any] = {
            "provisioning.migration_enabled": True,
            "provisioning.migration_spool_dir": self.spool.name,
        }
        settings_patch = patch(
            "apps.settings.services.SettingsService.get_setting",
            side_effect=lambda key, default=None: self.settings_values.get(key, default),
        )
        settings_patch.start()
        self.addCleanup(settings_patch.stop)
        self.source_gateway = MockVirtualminGateway(server_hostname=self.server.hostname)
        self.target_gateway = MockVirtualminGateway(server_hostname=self.target.hostname)
        self.source_gateway.seed_domain(
            self.account.domain, username=self.account.virtualmin_username, enabled=True
        )
        self.gateways = {"source": self.source_gateway, "target": self.target_gateway}
        self.events: list[tuple[str, str, dict[str, Any], int | None]] = []
        self.effects: dict[tuple[str, str], Any] = {}
        self.original_calls = {side: gateway.call for side, gateway in self.gateways.items()}
        for side, gateway in self.gateways.items():
            call_patch = patch.object(
                gateway, "call",
                side_effect=lambda program, params=None, _side=side, **kwargs: self._call(
                    _side, program, params or {}, **kwargs
                ),
            )
            call_patch.start()
            self.addCleanup(call_patch.stop)
        gateway_patch = patch(
            "apps.provisioning.virtualmin_migration_service.VirtualminGateway",
            side_effect=lambda config: (
                self.source_gateway if config.server.pk == self.server.pk else self.target_gateway
            ),
        )
        self.gateway_factory = gateway_patch.start()
        self.addCleanup(gateway_patch.stop)
        self.failed_playbook = ""
        ansible_patch = patch("apps.provisioning.virtualmin_migration_service.AnsibleService")
        self.ansible = ansible_patch.start()
        self.addCleanup(ansible_patch.stop)
        self.ansible.return_value.run_playbook.side_effect = self._transport
        enqueue_patch = patch("apps.provisioning.virtualmin_tasks.async_task", return_value="migration-task")
        self.enqueue = enqueue_patch.start()
        self.addCleanup(enqueue_patch.stop)

    def _call(self, side: str, program: str, params: dict[str, Any], **kwargs: Any) -> Any:
        self.events.append((side, program, params, kwargs.get("timeout_seconds")))
        if program == "restore-domain":
            migration = VirtualminMigration.objects.get(account=self.account)
            self.assertTrue(migration.restore_issued)
            self.assertEqual(migration.status, "restoring")
        effect = self.effects.get((side, program))
        if isinstance(effect, Exception):
            raise effect
        if callable(effect):
            return effect()
        if effect is not None:
            return effect
        return self.original_calls[side](program, params, **kwargs)

    def _transport(
        self, deployment: NodeDeployment, playbook: str,
        extra_vars: dict[str, Any] | None = None, timeout_seconds: int | None = None,
    ) -> Any:
        self.assertEqual(timeout_seconds, 3600)
        self.assertIsNotNone(extra_vars)
        assert extra_vars is not None
        if "fetch" in playbook:
            self.assertEqual(deployment.virtualmin_server_id, self.server.pk)
            self.assertGreater(extra_vars["spool_free_bytes"], 0)
        else:
            self.assertEqual(deployment.virtualmin_server_id, self.target.pk)
            self.assertEqual(extra_vars["expected_sha256"], "a" * 64)
            self.target_gateway._archives.update(deepcopy(self.source_gateway._archives))
        return Ok(AnsibleResult(
            success=playbook != self.failed_playbook,
            playbook=playbook,
            stdout=f'MIGRATE_SHA256={"a" * 64}',
            stderr="",
            return_code=0 if playbook != self.failed_playbook else 2,
        ))

    def _start(self) -> VirtualminMigration:
        with self.captureOnCommitCallbacks(execute=True):
            result = VirtualminMigrationService().start_migration(
                self.account, self.target, initiated_by=self.staff
            )
        self.assertTrue(result.is_ok(), result)
        return result.unwrap()

    def _run(self, migration: VirtualminMigration) -> VirtualminMigration:
        result = virtualmin_tasks.run_virtualmin_migration(str(migration.pk))
        self.assertTrue(result["success"], result)
        migration.refresh_from_db()
        return migration

    def _programs(self, side: str) -> list[str]:
        return [program for event_side, program, _, _ in self.events if event_side == side]

    def _error(self, side: str, program: str, *, unknown: bool = False) -> Any:
        return Err(
            VirtualminAPIError("injected failure", self.gateways[side].server_hostname, program),
            retriability=Retriability.UNKNOWN if unknown else Retriability.NOT_RETRIABLE,
        )

    def _partial_restore_error(self) -> Any:
        self.target_gateway.seed_domain(
            self.account.domain, username=self.account.virtualmin_username, enabled=False
        )
        return self._error("target", "restore-domain")

    def _reservation(self) -> None:
        service = Service.objects.create(
            customer=self.customer, service_plan=self.plan, currency=self.currency,
            service_name="reserved.example.com", domain="reserved.example.com",
            username="reserved", billing_cycle="monthly", price="10.00", status="active",
        )
        account = VirtualminAccount.objects.create(
            service=service, server=self.server, domain=service.domain,
            virtualmin_username="reserved", encrypted_password=self.account.encrypted_password,
        )
        VirtualminMigration.objects.create(
            account=account, source_server=self.server, target_server=self.target
        )
        VirtualminServer.objects.filter(pk=self.target.pk).update(max_domains=1, current_domains=0)


class MigrationTests(MigrationTestBase):
    def test_happy_path_order_evidence_repoint_and_audit(self) -> None:
        transitions: list[str] = []
        saves: list[set[str]] = []
        transition = VirtualminMigration.transition
        save = VirtualminAccount.save

        def record_transition(
            instance: VirtualminMigration, token: Any, before: str, after: str, **fields: Any
        ) -> bool:
            changed = transition(instance, token, before, after, **fields)
            if changed and before != after:
                transitions.append(after)
            return changed

        def record_save(instance: VirtualminAccount, *args: Any, **kwargs: Any) -> None:
            if instance.pk == self.account.pk:
                saves.append(set(kwargs.get("update_fields") or []))
            save(instance, *args, **kwargs)

        with (
            patch.object(VirtualminMigration, "transition", new=record_transition),
            patch.object(VirtualminAccount, "save", new=record_save),
        ):
            migration = self._run(self._start())
        self.assertEqual(transitions, [
            "quiescing", "backing_up", "fetching", "pushing", "restoring",
            "verifying", "activating", "repointing", "completed",
        ])
        source = self._programs("source")
        disable_index = source.index("disable-domain")
        self.assertEqual(source[disable_index + 1], "list-domains")
        self.assertLess(disable_index + 1, source.index("backup-domain"))
        self.assertIn("enable-domain", self._programs("target"))
        self.assertEqual(migration.archive_sha256, "a" * 64)
        self.assertTrue(any("server" in fields for fields in saves))
        self.account.refresh_from_db()
        self.server.refresh_from_db()
        self.target.refresh_from_db()
        self.assertEqual(self.account.server_id, self.target.pk)
        self.assertEqual(self.server.current_domains, 10)
        # Completion accounts for the restored domain immediately — the
        # reservation row died with the terminal status.
        self.assertEqual(self.target.current_domains, 1)
        self.assertEqual(VirtualminMigration.active_reservations(self.target), 0)
        self.assertFalse(account_has_active_migration(self.account))
        self.assertFalse(self.source_gateway.domain_state_of(self.account.domain).enabled)
        self.assertTrue(self.target_gateway.domain_state_of(self.account.domain).enabled)
        self.assertTrue(AuditEvent.objects.filter(
            action="virtualmin_migration_completed", object_id=str(migration.pk)
        ).exists())
        self.assertGreaterEqual(self.enqueue.call_args.kwargs["timeout"], 10800)
        for _, program, _, timeout in self.events:
            if program in {"backup-domain", "restore-domain"}:
                self.assertEqual(timeout, 1800)

    def test_preflight_rejections(self) -> None:
        cases = [
            ("disabled", lambda: self.settings_values.update({"provisioning.migration_enabled": False})),
            ("source inactive", lambda: VirtualminServer.objects.filter(pk=self.server.pk).update(
                status="maintenance"  # fsm-bypass: preflight fixture.
            )),
            ("target inactive", lambda: VirtualminServer.objects.filter(pk=self.target.pk).update(
                status="maintenance"  # fsm-bypass: preflight fixture.
            )),
            ("source manual registration", lambda: NodeDeployment.objects.filter(
                virtualmin_server=self.server
            ).delete()),
            ("target manual registration", lambda: NodeDeployment.objects.filter(
                virtualmin_server=self.target
            ).delete()),
            ("full", lambda: VirtualminServer.objects.filter(pk=self.target.pk).update(
                current_domains=1000
            )),
            ("reserved", self._reservation),
            ("unhealthy", lambda: VirtualminServer.objects.filter(pk=self.target.pk).update(
                health_check_error="unreachable"
            )),
            ("local multi-domain", lambda: VirtualminAccount.objects.filter(pk=self.account.pk).update(
                domains=[self.account.domain, "extra.example.com"]
            )),
            ("second migration", lambda: VirtualminMigration.objects.create(
                account=self.account, source_server=self.server, target_server=self.target
            )),
        ]
        for label, mutate in cases:
            with self.subTest(case=label), transaction.atomic():
                self.settings_values["provisioning.migration_enabled"] = True
                mutate()
                result = VirtualminMigrationService().start_migration(
                    self.account, self.target, initiated_by=self.staff
                )
                self.assertTrue(result.is_err(), result)
                if "manual registration" in label:
                    self.assertIn("manual registration", result.unwrap_err())
                transaction.set_rollback(True)
        self.settings_values["provisioning.migration_enabled"] = True
        self.assertTrue(VirtualminMigrationService().start_migration(
            self.account, self.server, initiated_by=self.staff
        ).is_err())
        self.assertNotIn("disable-domain", self._programs("source"))
        self.enqueue.assert_not_called()

    def test_remote_preflight_failures_are_recorded(self) -> None:
        for case in ("collision", "target listing error", "remote multi-domain"):
            with self.subTest(case=case), transaction.atomic():
                self.target_gateway._domains.clear()
                self.source_gateway._domains = {
                    self.account.domain: self.source_gateway.domain_state_of(self.account.domain)
                }
                self.effects.clear()
                if case == "collision":
                    self.target_gateway.seed_domain(self.account.domain, username="another-owner")
                elif case == "target listing error":
                    self.effects[("target", "list-domains")] = self._error("target", "list-domains")
                else:
                    self.source_gateway.seed_domain(
                        "extra.example.com", username=self.account.virtualmin_username
                    )
                result = VirtualminMigrationService().start_migration(
                    self.account, self.target, initiated_by=self.staff
                )
                self.assertTrue(result.is_err(), result)
                self.assertEqual(VirtualminMigration.objects.get(account=self.account).status, "failed")
                transaction.set_rollback(True)
        self.assertNotIn("disable-domain", self._programs("source"))

    def test_quiesce_noop_rolls_back_without_backup_or_enable(self) -> None:
        self.effects[("source", "disable-domain")] = lambda: self.original_calls["source"]("info", {})
        migration = self._run(self._start())
        self.assertEqual(migration.status, "rolled_back")
        self.assertIsNone(migration.source_disabled_at)
        self.assertNotIn("backup-domain", self._programs("source"))
        self.assertNotIn("enable-domain", self._programs("source"))
        self.ansible.assert_not_called()

    def test_backup_explicit_error_rolls_back_and_verifies_enable(self) -> None:
        self.effects[("source", "backup-domain")] = self._error("source", "backup-domain")
        migration = self._run(self._start())
        self.assertEqual(migration.status, "rolled_back")
        self.assertEqual(self._programs("source")[-2:], ["enable-domain", "list-domains"])
        self.assertTrue(self.source_gateway.domain_state_of(self.account.domain).enabled)

    def test_backup_unknown_retains_quiesce_without_retry(self) -> None:
        self.effects[("source", "backup-domain")] = self._error("source", "backup-domain", unknown=True)
        migration = self._run(self._start())
        self.assertEqual(migration.status, "needs_review")
        self.assertEqual(self._programs("source").count("backup-domain"), 1)
        self.assertNotIn("enable-domain", self._programs("source"))
        self.assertFalse(self.source_gateway.domain_state_of(self.account.domain).enabled)
        self.assertTrue(account_has_active_migration(self.account))

    def test_fetch_and_push_application_failure_roll_back(self) -> None:
        for playbook in ("virtualmin_migrate_fetch.yml", "virtualmin_migrate_push.yml"):
            with self.subTest(playbook=playbook), transaction.atomic():
                self.source_gateway.domain_state_of(self.account.domain).enabled = True
                self.failed_playbook = playbook
                migration = self._run(self._start())
                self.assertEqual(migration.status, "rolled_back")
                self.assertEqual(self._programs("source")[-2:], ["enable-domain", "list-domains"])
                self.assertNotIn("restore-domain", self._programs("target"))
                transaction.set_rollback(True)

    def test_restore_explicit_error_deletes_partial_target_and_rolls_back(self) -> None:
        self.effects[("target", "restore-domain")] = self._partial_restore_error
        migration = self._run(self._start())
        self.assertEqual(migration.status, "rolled_back")
        self.assertIn("delete-domain", self._programs("target"))
        self.assertIsNone(self.target_gateway.domain_state_of(self.account.domain))
        self.assertEqual(self._programs("source")[-2:], ["enable-domain", "list-domains"])

    def test_restore_ambiguity_has_no_listing_inference_or_compensation(self) -> None:
        self.effects[("target", "restore-domain")] = self._error("target", "restore-domain", unknown=True)
        migration = self._run(self._start())
        self.assertEqual(migration.status, "needs_review")
        target = self._programs("target")
        self.assertEqual(target[target.index("restore-domain"):], ["restore-domain"])
        self.assertNotIn("enable-domain", self._programs("source"))

    def test_verify_owner_quota_and_features_mismatch_require_review(self) -> None:
        for field, value in (
            ("username", "wrong-owner"), ("disk_quota_mb", 9999), ("features", ["web"])
        ):
            with self.subTest(field=field), transaction.atomic():
                self.source_gateway.domain_state_of(self.account.domain).enabled = True
                self.target_gateway._domains.clear()
                migration = self._start()

                def restore_mismatch(migration=migration, field=field, value=value) -> Any:
                    result = self.original_calls["target"](
                        "restore-domain",
                        # Remote path on the Virtualmin node, not a local tempfile.
                        {"domain": self.account.domain, "source": f"/tmp/{migration.archive_name}"},  # noqa: S108
                    )
                    setattr(self.target_gateway.domain_state_of(self.account.domain), field, value)
                    return result

                self.effects[("target", "restore-domain")] = restore_mismatch
                self._run(migration)
                self.assertEqual(migration.status, "needs_review")
                self.assertNotIn("delete-domain", self._programs("target"))
                self.assertNotIn("enable-domain", self._programs("source"))
                transaction.set_rollback(True)

    def test_enable_failure_requires_review(self) -> None:
        self.effects[("target", "enable-domain")] = self._error("target", "enable-domain")
        migration = self._run(self._start())
        self.assertEqual(migration.status, "needs_review")
        self.assertNotIn("delete-domain", self._programs("target"))
        self.assertNotIn("enable-domain", self._programs("source"))

    def test_post_activation_transition_failure_never_rolls_back(self) -> None:
        migration = self._start()
        transition = VirtualminMigration.transition

        def fail_repoint(
            instance: VirtualminMigration, token: Any, before: str, after: str, **fields: Any
        ) -> bool:
            if before == "activating" and after == "repointing":
                return False
            return transition(instance, token, before, after, **fields)

        with patch.object(VirtualminMigration, "transition", new=fail_repoint):
            self._run(migration)
        self.assertEqual(migration.status, "needs_review")
        self.assertTrue(self.target_gateway.domain_state_of(self.account.domain).enabled)
        self.assertNotIn("delete-domain", self._programs("target"))
        self.assertNotIn("enable-domain", self._programs("source"))
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)

    def test_compensation_failure_is_audited(self) -> None:
        self.effects[("source", "backup-domain")] = self._error("source", "backup-domain")
        self.effects[("source", "enable-domain")] = self._error("source", "enable-domain")
        migration = self._run(self._start())
        self.assertEqual(migration.status, "needs_review")
        event = AuditEvent.objects.get(
            action="virtualmin_migration_needs_review", object_id=str(migration.pk)
        )
        self.assertTrue(event.metadata["compensation_failure"])

    def test_resume_busy_and_interrupted_states(self) -> None:
        for status in ("pending", "backing_up", "restoring", "verifying"):
            with self.subTest(status=status), transaction.atomic():
                self.source_gateway.domain_state_of(self.account.domain).enabled = True
                self.target_gateway._domains.clear()
                migration = self._start()
                token = uuid4()
                self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
                job = self._failed_job("migrate_domain", parameters={"migration_id": str(migration.pk)})
                if status == "pending":
                    before = len(self.events)
                    result = resume_migration(job)
                    self.assertEqual(result.unwrap(), {
                        "action": "busy", "migration_id": str(migration.pk), "lease_acquired": False
                    })
                    self.assertEqual(len(self.events), before)
                else:
                    self.assertTrue(migration.transition(
                        token, "pending", status,
                        restore_issued=status in {"restoring", "verifying"},
                        lease_token=None, worker_lease_expires_at=None,
                    ))
                    self.source_gateway.domain_state_of(self.account.domain).enabled = False
                    if status == "verifying":
                        self.target_gateway._domains[self.account.domain] = deepcopy(
                            self.source_gateway.domain_state_of(self.account.domain)
                        )
                    result = resume_migration(job)
                    self.assertTrue(result.is_ok(), result)
                    migration.refresh_from_db()
                    expected = "completed" if status == "verifying" else "needs_review"
                    self.assertEqual(migration.status, expected)
                transaction.set_rollback(True)

    def test_presuspended_account_stays_suspended(self) -> None:
        # fsm-bypass: establish a previously suspended account fixture.
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="suspended")
        self.source_gateway.domain_state_of(self.account.domain).enabled = False
        migration = self._run(self._start())
        self.assertEqual(migration.status, "completed")
        self.assertIsNone(migration.source_disabled_at)
        self.assertNotIn("disable-domain", self._programs("source"))
        self.assertNotIn("enable-domain", self._programs("target"))
        self.assertFalse(self.target_gateway.domain_state_of(self.account.domain).enabled)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(self.account.server_id, self.target.pk)

    def test_wire_truth_backup_timeout_and_restore_outcomes(self) -> None:
        self.gateway_factory.side_effect = lambda config: VirtualminGateway(
            replace(config, use_credential_vault=False)
        )
        for side, program, failure in (
            ("source", "backup-domain", "timeout"),
            ("target", "restore-domain", "timeout"),
            ("target", "restore-domain", "bare"),
            ("target", "restore-domain", "explicit"),
        ):
            with self.subTest(program=program, failure=failure), transaction.atomic():
                self.events.clear()
                self.target_gateway._domains.clear()
                self.source_gateway.domain_state_of(self.account.domain).enabled = True
                wire_calls: list[tuple[str, str, float]] = []

                def wire(
                    method: str,
                    url: str,
                    *,
                    bound=(wire_calls, side, program, failure),
                    **kwargs: Any,
                ) -> requests.Response:
                    wire_calls, side, program, failure = bound
                    host_side = "source" if self.server.hostname in url else "target"
                    params = kwargs["params"]
                    operation = params["program"]
                    wire_calls.append((host_side, operation, kwargs["policy"].timeout_seconds))
                    if (host_side, operation) == (side, program):
                        self.assertEqual(kwargs["policy"].timeout_seconds, 1800.0)
                        if failure == "timeout":
                            raise requests.exceptions.ReadTimeout("response lost")
                        if failure == "explicit":
                            self.target_gateway.seed_domain(
                                self.account.domain,
                                username=self.account.virtualmin_username,
                                enabled=False,
                            )
                            payload = {"status": "error", "error": "restore failed"}
                        else:
                            payload = {"data": []}
                    else:
                        result = self.original_calls[host_side](operation, params)
                        self.assertTrue(result.is_ok(), result)
                        payload = json.loads(result.unwrap().raw_response)
                    response = requests.Response()
                    response.status_code = 200
                    response._content = json.dumps(payload).encode()
                    response._content_consumed = True
                    return response

                with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=wire):
                    migration = self._run(self._start())
                expected = "rolled_back" if failure == "explicit" else "needs_review"
                self.assertEqual(migration.status, expected)
                self.assertEqual(sum(
                    (call_side, operation) == (side, program)
                    for call_side, operation, _ in wire_calls
                ), 1)
                if failure != "explicit":
                    index = next(
                        i for i, item in enumerate(wire_calls) if item[:2] == (side, program)
                    )
                    self.assertEqual(wire_calls[index + 1:], [])
                transaction.set_rollback(True)

    def test_account_sync_lock_active_assignment_and_remote_disabled_guards(self) -> None:
        self.client.force_login(self.staff)
        migration = self._start()
        self.target_gateway.seed_domain(
            self.account.domain, username=self.account.virtualmin_username, enabled=True
        )
        with patch.object(
            VirtualminProvisioningService, "_get_gateway",
            side_effect=lambda server: (
                self.source_gateway if server.pk == self.server.pk else self.target_gateway
            ),
        ):
            response = self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
            self.assertEqual(response.status_code, 302)
            self.account.refresh_from_db()
            self.assertIsNone(self.account.last_sync_at)
            token = uuid4()
            self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
            self.assertTrue(migration.transition(token, "pending", "failed"))
            self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
            self.account.refresh_from_db()
            self.assertEqual(self.account.server_id, self.server.pk)
            self.assertIsNotNone(self.account.last_sync_at)
            VirtualminServer.objects.filter(pk=self.server.pk).update(
                status="maintenance"  # fsm-bypass: inactive-source sync fixture.
            )
            self.target_gateway.domain_state_of(self.account.domain).enabled = False
            self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
            self.account.refresh_from_db()
            self.assertEqual(self.account.server_id, self.server.pk)
            self.target_gateway.domain_state_of(self.account.domain).enabled = True
            self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
            self.account.refresh_from_db()
            self.assertEqual(self.account.server_id, self.target.pk)

    def test_enforcement_skips_locked_account(self) -> None:
        self._start()
        service = VirtualminProvisioningService(self.server)
        with patch.object(service, "_get_gateway") as gateway:
            result = service.enforce_praho_state(self.account, force=True)
        self.assertEqual(result.unwrap()["action"], "migration_locked")
        gateway.assert_not_called()

    def test_reconciliation_skips_locked_account(self) -> None:
        self._start()
        # fsm-bypass: make ordinary convergence attempt an unsuspend.
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="suspended")
        with patch.object(VirtualminProvisioningService, "unsuspend_account") as unsuspend:
            result = virtualmin_tasks.reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertEqual(result["action"], "migration_locked")
        unsuspend.assert_not_called()

    def test_lifecycle_tasks_direct_calls_and_retries_skip_locked_account(self) -> None:
        self._start()
        for task, method, operation in (
            (virtualmin_tasks.suspend_virtualmin_account, "suspend_account", "suspend_domain"),
            (virtualmin_tasks.unsuspend_virtualmin_account, "unsuspend_account", "unsuspend_domain"),
            (virtualmin_tasks.delete_virtualmin_account, "delete_account", "delete_domain"),
        ):
            with self.subTest(operation=operation):
                with patch.object(VirtualminProvisioningService, method) as mutation:
                    result = task(str(self.account.pk))
                self.assertEqual(result["action"], "migration_locked")
                mutation.assert_not_called()
                service = VirtualminProvisioningService(self.server)
                with patch.object(service, "_get_gateway") as gateway:
                    direct = getattr(service, method)(self.account)
                    retry = service.retry_job(self._failed_job(operation))
                self.assertTrue(direct.is_err())
                self.assertIn("migration", direct.unwrap_err().lower())
                self.assertTrue(retry.is_err())
                gateway.assert_not_called()

    def test_ui_targets_post_kill_switch_and_routing_note(self) -> None:
        self.client.force_login(self.staff)
        ineligible = VirtualminServer.objects.create(
            name="unhealthy-target", hostname="unhealthy-target.example.com", api_username="test"
        )
        url = reverse("provisioning:virtualmin_account_migrate", args=[self.account.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        choices = list(response.context["form"].fields["target_server"].queryset)
        self.assertEqual([server.pk for server in choices], [self.target.pk])
        self.assertNotIn(ineligible, choices)
        self.settings_values["provisioning.migration_enabled"] = False
        response = self.client.post(url, {"target_server": str(self.target.pk), "confirm": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(VirtualminMigration.objects.exists())
        self.enqueue.assert_not_called()
        self.settings_values["provisioning.migration_enabled"] = True
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(url, {"target_server": str(self.target.pk), "confirm": "on"})
        self.assertEqual(response.status_code, 302)
        migration = VirtualminMigration.objects.get(account=self.account)
        self.enqueue.assert_called_once()
        self._run(migration)
        self.assertFalse(migration.routing_note_shown)
        with patch("apps.provisioning.virtualmin_views.VirtualminBackupService") as backups:
            backups.return_value.list_backups.return_value = Ok([])
            response = self.client.get(reverse(
                "provisioning:virtualmin_account_detail", args=[self.account.pk]
            ))
        self.assertContains(response, "routing/DNS")
        migration.refresh_from_db()
        self.assertTrue(migration.routing_note_shown)


class MigrationAnsibleTimeoutTests(SimpleTestCase):
    def test_override_default_and_timeout_reporting(self) -> None:
        service = object.__new__(AnsibleService)
        service.timeout = 30
        service._ansible_path = "/usr/bin/ansible-playbook"
        service._ssh_manager = MagicMock()
        service._ssh_manager.get_private_key_file.return_value = Ok(Path("nonexistent-migration-key"))
        deployment = MagicMock(ipv4_address="203.0.113.1", hostname="migration-node")
        with (
            patch.object(service, "_wait_for_ssh", return_value=Ok(True)),
            patch.object(service, "_configured_known_hosts_covers", return_value=True),
            patch.object(service, "_generate_inventory", return_value=Path("nonexistent-migration-inventory")),
            patch.object(service, "_build_vars", return_value={}),
            patch.object(service, "_write_vars_file", return_value=Path("nonexistent-migration-vars")),
            patch.object(service, "_build_ansible_env", return_value={}),
            patch("apps.infrastructure.ansible_service.subprocess.run") as run,
        ):
            run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            for requested, expected in ((None, 30), (3600, 3600)):
                with self.subTest(timeout=requested):
                    result = service.run_playbook(
                        deployment, "virtualmin_migrate_fetch.yml", timeout_seconds=requested
                    )
                    self.assertTrue(result.unwrap().success)
                    self.assertEqual(run.call_args.kwargs["timeout"], expected)
            run.side_effect = subprocess.TimeoutExpired("ansible-playbook", 3600)
            result = service.run_playbook(
                deployment, "virtualmin_migrate_push.yml", timeout_seconds=3600
            )
            self.assertFalse(result.unwrap().success)
            self.assertIn("3600", result.unwrap().stderr)
        self.assertEqual(service.timeout, 30)
