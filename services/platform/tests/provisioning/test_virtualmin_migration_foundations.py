"""Round 1a contracts for Virtualmin migration foundations."""

from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, cast
from unittest.mock import patch
from uuid import uuid4

import requests
from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError, transaction
from django.db.models.deletion import ProtectedError
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.common.types import Retriability
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_gateway import (
    VirtualminConfig,
    VirtualminGateway,
    VirtualminTransientError,
)
from apps.provisioning.virtualmin_models import (
    VirtualminAccount,
    VirtualminProvisioningJob,
    VirtualminServer,
)
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.provisioning.virtualmin_tasks import process_failed_virtualmin_jobs, retry_virtualmin_job
from tests.mocks.virtualmin_mock import MockVirtualminGateway

if TYPE_CHECKING:
    from apps.provisioning.virtualmin_migration_models import VirtualminMigration


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "virtualmin-migration-foundations",
        }
    },
)
class VirtualminMigrationFoundationTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Migration SRL",
            customer_type="company",
            status="active",
            primary_email="migration@example.com",
            company_name="Migration SRL",
        )
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.plan = ServicePlan.objects.create(
            name="Migration Hosting",
            plan_type="shared_hosting",
            price_monthly=Decimal("10.00"),
        )
        self.server = VirtualminServer.objects.create(
            name="migration-source",
            hostname="migration-source.example.com",
            api_username="praho-acl",
            api_port=10000,
            use_ssl=True,
            status="active",
            max_domains=1000,
            current_domains=10,
            last_health_check=timezone.now(),
        )
        self.server.set_api_password("test_password")
        self.server.save()
        self.target = VirtualminServer.objects.create(
            name="migration-target",
            hostname="migration-target.example.com",
            api_username="praho-acl",
            api_port=10000,
            use_ssl=True,
            status="active",
            max_domains=1000,
            current_domains=0,
            last_health_check=timezone.now(),
        )
        self.target.set_api_password("target_password")
        self.target.save()
        self.account = self._account_for("foundation.example.com")

    def _account_for(self, domain: str) -> VirtualminAccount:
        username = domain.split(".", 1)[0]
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=domain,
            domain=domain,
            username=username,
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="active",
        )
        account = VirtualminAccount.objects.create(
            domain=domain,
            service=service,
            server=VirtualminServer.objects.get(pk=self.server.pk),
            virtualmin_username=username,
            template_name="Default",
            status="error",
            praho_customer_id=self.customer.pk,
            praho_service_id=service.pk,
        )
        account.set_password("account_password")
        account.save()
        return account

    def _migration_model(self) -> type[VirtualminMigration]:
        # Defer lookup so the scheduler discriminator runs against current source.
        return cast(
            "type[VirtualminMigration]",
            apps.get_model("provisioning", "VirtualminMigration"),
        )

    def _migration(self, **overrides: object) -> VirtualminMigration:
        values: dict[str, object] = {
            "account": self.account,
            "source_server": self.server,
            "target_server": self.target,
            "reason": "manual",
        }
        values.update(overrides)
        return self._migration_model().objects.create(**values)

    def _job(self, **overrides: object) -> VirtualminProvisioningJob:
        values: dict[str, object] = {
            "operation": "migrate_domain",
            "server": self.server,
            "account": self.account,
            "correlation_id": f"foundation_{uuid4()}",
            "status": "failed",
            "retry_count": 0,
            "next_retry_at": timezone.now() - timedelta(minutes=1),
        }
        values.update(overrides)
        return VirtualminProvisioningJob.objects.create(**values)

    def test_mf_scheduler_dispatches_migration_to_missing_row_result(self) -> None:
        job = self._job(parameters={"migration_id": str(uuid4())})
        with patch("apps.provisioning.virtualmin_tasks.async_task", return_value="migration-task") as enqueue:
            sweep = process_failed_virtualmin_jobs()

        self.assertTrue(sweep["success"], sweep)
        self.assertEqual(sweep["results"]["retried_jobs"], 1)
        self.assertEqual(sweep["results"]["skipped_jobs"], 0)
        job.refresh_from_db()
        self.assertEqual(job.status, "pending")
        self.assertIsNotNone(job.claimed_at)
        nonce = job.claimed_at.isoformat()
        self.assertEqual(
            enqueue.call_args.args,
            ("apps.provisioning.virtualmin_tasks.retry_virtualmin_job", str(job.pk), nonce),
        )

        result = retry_virtualmin_job(str(job.pk), nonce)
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "migration not found")
        job.refresh_from_db()
        self.assertEqual(job.status, "running")
        self.assertIsNotNone(job.claimed_at)

    def test_mf_busy_dispatch_is_observable_and_claim_recovery_is_bounded(self) -> None:
        migration = self._migration()
        job = self._job(parameters={"migration_id": str(migration.pk)})
        clock = timezone.now()

        for attempt in range(1, job.max_retries + 1):
            with (
                patch("django.utils.timezone.now", return_value=clock),
                patch("apps.provisioning.virtualmin_tasks.async_task", return_value=f"migration-{attempt}"),
            ):
                sweep = process_failed_virtualmin_jobs()
                self.assertEqual(sweep["results"]["retried_jobs"], 1)
                job.refresh_from_db()
                self.assertIsNotNone(job.claimed_at)
                nonce = job.claimed_at.isoformat()
                result = retry_virtualmin_job(str(job.pk), nonce)
                duplicate = retry_virtualmin_job(str(job.pk), nonce)

            self.assertEqual(
                result,
                {
                    "success": True,
                    "job_id": str(job.pk),
                    "action": "busy",
                    "migration_id": str(migration.pk),
                    "lease_acquired": True,
                },
            )
            self.assertEqual(duplicate["action"], "stale_claim_discarded")
            job.refresh_from_db()
            self.assertEqual(job.status, "running")
            self.assertEqual(job.retry_count, attempt)
            self.assertIsNotNone(job.claimed_at)
            migration.refresh_from_db()
            self.assertEqual(migration.status, "pending")
            self.assertIsNotNone(migration.lease_token)
            self.assertEqual(migration.worker_lease_expires_at, clock + timedelta(minutes=5))

            clock += timedelta(minutes=31)
            with (
                patch("django.utils.timezone.now", return_value=clock),
                patch("apps.provisioning.virtualmin_tasks.async_task") as enqueue,
            ):
                recovery = process_failed_virtualmin_jobs()
            self.assertEqual(recovery["results"]["recovered_claims"], 1)
            enqueue.assert_not_called()
            job.refresh_from_db()
            self.assertEqual(job.status, "failed")
            self.assertIsNone(job.claimed_at)
            if attempt < job.max_retries:
                self.assertEqual(job.next_retry_at, clock + timedelta(minutes=5))
            else:
                self.assertIsNone(job.next_retry_at)
                self.assertEqual(recovery["results"]["exhausted_jobs"], 1)
            clock += timedelta(minutes=6)

        self.assertEqual(VirtualminProvisioningJob.objects.filter(account=self.account).count(), 1)
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)

    def test_mf_stub_reports_contention_and_invalid_reference(self) -> None:
        from apps.provisioning.virtualmin_migration_service import (  # noqa: PLC0415
            resume_migration,
        )

        migration = self._migration()
        owner = uuid4()
        self.assertTrue(migration.acquire_lease(owner, timedelta(minutes=5)))
        job = self._job(parameters={"migration_id": str(migration.pk)})
        result = resume_migration(job)
        self.assertTrue(result.is_ok())
        self.assertEqual(
            result.unwrap(),
            {"action": "busy", "migration_id": str(migration.pk), "lease_acquired": False},
        )
        migration.refresh_from_db()
        self.assertEqual(migration.lease_token, owner)

        for parameters in ({}, {"migration_id": "invalid"}, {"migration_id": str(uuid4())}):
            with self.subTest(parameters=parameters):
                job.parameters = parameters
                missing = resume_migration(job)
                self.assertTrue(missing.is_err())
                self.assertEqual(missing.unwrap_err(), "migration not found")

    def test_mf_model_defaults_and_protected_relationships(self) -> None:
        migration = self._migration()
        migration.refresh_from_db()
        self.assertEqual(migration.archive_name, f"migration_{migration.pk}.tar.gz")
        self.assertEqual(migration.status, "pending")
        self.assertEqual(migration.reason, "manual")
        self.assertEqual(migration.archive_sha256, "")
        self.assertEqual(migration.error_detail, "")
        self.assertEqual(migration.pre_migration_snapshot, {})
        self.assertFalse(migration.restore_issued)
        self.assertFalse(migration.routing_note_shown)
        self.assertIsNone(migration.source_disabled_at)
        self.assertIsNone(migration.lease_token)
        self.assertIsNone(migration.worker_lease_expires_at)
        self.assertIsNone(migration.initiated_by_id)
        self.assertIsNotNone(migration.created_at)
        self.assertIsNotNone(migration.updated_at)
        migration.full_clean()

        for protected in (self.account, self.server, self.target):
            with (
                self.subTest(model=type(protected).__name__, pk=protected.pk),
                self.assertRaises(ProtectedError),
                transaction.atomic(),
            ):
                protected.delete()

    def test_mf_lease_acquisition_and_renewal_are_single_updates(self) -> None:
        migration = self._migration()
        owner, contender = uuid4(), uuid4()
        now = timezone.now()
        with patch("django.utils.timezone.now", return_value=now):
            with self.assertNumQueries(1):
                self.assertTrue(migration.acquire_lease(owner, timedelta(seconds=60)))
            with self.assertNumQueries(1):
                self.assertFalse(migration.acquire_lease(contender, timedelta(seconds=60)))
            with self.assertNumQueries(1):
                self.assertFalse(migration.renew_lease(contender, timedelta(seconds=120)))
            with self.assertNumQueries(1):
                self.assertTrue(migration.renew_lease(owner, timedelta(seconds=120)))
        migration.refresh_from_db()
        self.assertEqual(migration.lease_token, owner)
        self.assertEqual(migration.worker_lease_expires_at, now + timedelta(seconds=120))

    def test_mf_expired_lease_allows_exact_boundary_takeover(self) -> None:
        migration = self._migration()
        previous, replacement = uuid4(), uuid4()
        now = timezone.now()
        with patch("django.utils.timezone.now", return_value=now):
            self.assertTrue(migration.acquire_lease(previous, timedelta(seconds=60)))
        with patch("django.utils.timezone.now", return_value=now + timedelta(seconds=59)):
            self.assertFalse(migration.acquire_lease(replacement, timedelta(seconds=60)))
        with patch("django.utils.timezone.now", return_value=now + timedelta(seconds=60)):
            self.assertFalse(migration.renew_lease(previous, timedelta(seconds=60)))
            with self.assertNumQueries(1):
                self.assertTrue(migration.acquire_lease(replacement, timedelta(seconds=60)))
            self.assertFalse(migration.renew_lease(previous, timedelta(seconds=60)))
        migration.refresh_from_db()
        self.assertEqual(migration.lease_token, replacement)
        self.assertEqual(migration.worker_lease_expires_at, now + timedelta(seconds=120))

    def test_mf_stale_token_and_wrong_status_change_nothing(self) -> None:
        migration = self._migration()
        owner, stale = uuid4(), uuid4()
        self.assertTrue(migration.acquire_lease(owner, timedelta(minutes=5)))
        model = self._migration_model()
        before = model.objects.values().get(pk=migration.pk)
        with self.assertNumQueries(1):
            self.assertFalse(migration.transition(stale, "pending", "restoring", restore_issued=True))
        self.assertEqual(model.objects.values().get(pk=migration.pk), before)
        with self.assertNumQueries(1):
            self.assertFalse(migration.transition(owner, "fetching", "restoring", restore_issued=True))
        self.assertEqual(model.objects.values().get(pk=migration.pk), before)
        with self.assertNumQueries(1):
            self.assertTrue(migration.transition(owner, "pending", "restoring", restore_issued=True))
        migration.refresh_from_db()
        self.assertEqual(migration.status, "restoring")
        self.assertTrue(migration.restore_issued)

    def test_mf_nonpositive_lease_ttl_is_rejected(self) -> None:
        migration = self._migration()
        for method in (migration.acquire_lease, migration.renew_lease):
            for ttl in (timedelta(0), timedelta(seconds=-1)):
                with (
                    self.subTest(method=method.__name__, ttl=ttl),
                    self.assertRaisesMessage(ValueError, "ttl must be positive"),
                ):
                    method(uuid4(), ttl)

    def test_mf_second_active_migration_is_rejected(self) -> None:
        self._migration()
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._migration()

    def test_mf_terminal_migrations_release_account_uniqueness(self) -> None:
        for status in ("completed", "failed", "rolled_back"):
            with self.subTest(status=status):
                account = self._account_for(f"terminal-{status}.example.com")
                self._migration(account=account, status=status)
                active = self._migration(account=account)
                self.assertEqual(active.status, "pending")

    def test_mf_needs_review_retains_account_uniqueness(self) -> None:
        self._migration(status="needs_review")
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._migration()

    def test_mf_reservations_count_only_nonterminal_target_rows(self) -> None:
        statuses = (
            "pending", "quiescing", "backing_up", "fetching", "pushing", "restoring",
            "verifying", "activating", "repointing", "completed", "failed",
            "needs_review", "rolled_back",
        )
        for index, status in enumerate(statuses):
            self._migration(
                account=self._account_for(f"reservation{index}.example.com"),
                status=status,
            )
        self._migration(source_server=self.target, target_server=self.server)
        model = self._migration_model()
        self.assertEqual(model.active_reservations(self.target), 10)
        self.assertEqual(model.active_reservations(self.server), 1)

    def test_mf_timeout_override_is_per_call_and_default_is_preserved(self) -> None:
        config = VirtualminConfig(server=self.server, timeout=11, use_credential_vault=False)
        gateway = VirtualminGateway(config)
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"status":"success","data":[]}'
        response._content_consumed = True

        with (
            patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=response) as request,
            patch(
                "apps.provisioning.virtualmin_gateway.get_virtualmin_timeouts",
                return_value={"API_REQUEST_TIMEOUT": 37},
            ),
        ):
            self.assertTrue(gateway.call("backup-domain", {"domain": self.account.domain}, timeout_seconds=600).is_ok())
            override_policy = request.call_args.kwargs["policy"]
            self.assertEqual(override_policy.timeout_seconds, 600.0)
            self.assertTrue(gateway.call("info", timeout_seconds=None).is_ok())
            default_policy = request.call_args.kwargs["policy"]
            self.assertEqual(default_policy.timeout_seconds, 37.0)
            self.assertTrue(gateway.call("info").is_ok())
            self.assertEqual(request.call_args.kwargs["policy"].timeout_seconds, 37.0)

        self.assertIsNot(override_policy, default_policy)
        self.assertEqual(override_policy.timeout_seconds, 600.0)
        self.assertEqual(override_policy.connect_timeout_seconds, default_policy.connect_timeout_seconds)
        self.assertEqual(config.timeout, 11)

    def test_mf_override_read_timeout_remains_unknown_without_replay(self) -> None:
        gateway = VirtualminGateway(VirtualminConfig(server=self.server, use_credential_vault=False))
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=requests.exceptions.ReadTimeout("lost response"),
        ) as request:
            result = gateway.call("backup-domain", {"domain": self.account.domain}, timeout_seconds=600)
        self.assertTrue(result.is_err())
        self.assertIsInstance(result.unwrap_err(), VirtualminTransientError)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
        request.assert_called_once()
        self.assertEqual(request.call_args.kwargs["policy"].timeout_seconds, 600.0)

    def test_mf_creation_counts_both_stale_server_instances(self) -> None:
        second = self._account_for("foundationsecond.example.com")
        self.assertIsNot(self.account.server, second.server)
        self.assertEqual(self.account.server.current_domains, 10)
        self.assertEqual(second.server.current_domains, 10)
        first_job = self._job(operation="create_domain", status="pending")
        second_job = self._job(operation="create_domain", account=second, status="pending")
        gateway = MockVirtualminGateway()

        with patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway):
            first_result = VirtualminProvisioningService(self.account.server)._execute_domain_creation(
                self.account, first_job
            )
            second_result = VirtualminProvisioningService(second.server)._execute_domain_creation(
                second, second_job
            )

        self.assertTrue(first_result.is_ok(), first_result)
        self.assertTrue(second_result.is_ok(), second_result)
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 12)
        self.assertEqual(second.server.current_domains, 12)
        self.assertEqual(len(gateway.get_calls("create-domain")), 2)

    def test_mf_mock_archive_roundtrip_and_overwrite_preserve_snapshot(self) -> None:
        gateway = MockVirtualminGateway()
        original = gateway.seed_domain(
            "archive.example.com", username="archiveowner", enabled=False,
            disk_quota_mb=4321, bandwidth_quota_mb=8765,
        )
        original.features = ["web", "dns"]
        snapshot = deepcopy(original)
        self.assertTrue(gateway.call(
            "backup-domain", {"domain": original.name, "dest": "migration.tar.gz"}
        ).unwrap().success)
        original.features.append("mail")
        self.assertTrue(gateway.call("delete-domain", {"domain": original.name}).unwrap().success)
        self.assertTrue(gateway.call(
            "restore-domain", {"domain": original.name, "source": "migration.tar.gz"}
        ).unwrap().success)
        self.assertEqual(gateway.domain_state_of(original.name), snapshot)

        gateway.seed_domain(original.name, username="differentowner", enabled=True, disk_quota_mb=999)
        self.assertTrue(gateway.call(
            "restore-domain", {"domain": original.name, "source": "migration.tar.gz"}
        ).unwrap().success)
        restored = gateway.domain_state_of(original.name)
        self.assertIsNotNone(restored)
        self.assertEqual(restored, snapshot)
        self.assertTrue(restored.disabled)
        restored.features.append("mysql")
        self.assertTrue(gateway.call(
            "restore-domain", {"domain": original.name, "source": "migration.tar.gz"}
        ).unwrap().success)
        self.assertEqual(gateway.domain_state_of(original.name), snapshot)
        self.assertEqual(len(gateway.get_calls("backup-domain")), 1)
        self.assertEqual(len(gateway.get_calls("restore-domain")), 3)
        self.assertTrue(all(call.result_success for call in gateway.get_calls()))

    def test_mf_mock_disabled_flag_tracks_existing_enable_contract(self) -> None:
        gateway = MockVirtualminGateway()
        domain = gateway.seed_domain("toggle.example.com")
        self.assertFalse(domain.disabled)
        self.assertTrue(gateway.call("disable-domain", {"domain": domain.name}).unwrap().success)
        self.assertTrue(domain.disabled)
        self.assertFalse(domain.enabled)
        self.assertTrue(gateway.call("enable-domain", {"domain": domain.name}).unwrap().success)
        self.assertFalse(domain.disabled)
        self.assertTrue(domain.enabled)

    def test_mf_mock_missing_archive_and_domain_operations_fail(self) -> None:
        gateway = MockVirtualminGateway()
        for program, params in (
            ("backup-domain", {"domain": "missing.example.com", "dest": "missing.tar.gz"}),
            ("disable-domain", {"domain": "missing.example.com"}),
            ("enable-domain", {"domain": "missing.example.com"}),
            ("restore-domain", {"domain": "missing.example.com", "source": "missing.tar.gz"}),
        ):
            with self.subTest(program=program):
                result = gateway.call(program, params)
                self.assertTrue(result.is_err(), result)
                self.assertFalse(gateway.get_calls(program)[-1].result_success)
        self.assertEqual(gateway.domain_count, 0)

    def test_mf_mock_reset_discards_archives(self) -> None:
        gateway = MockVirtualminGateway()
        domain = gateway.seed_domain("resetarchive.example.com")
        self.assertTrue(gateway.call(
            "backup-domain", {"domain": domain.name, "dest": "reset.tar.gz"}
        ).unwrap().success)
        gateway.reset()
        result = gateway.call("restore-domain", {"domain": domain.name, "source": "reset.tar.gz"})
        self.assertTrue(result.is_err())
        self.assertEqual(gateway.domain_count, 0)
        self.assertEqual(gateway.call_count, 1)

    def test_mf_audit_actions_pass_full_clean(self) -> None:
        content_type = ContentType.objects.get_for_model(self.account)
        for suffix in ("started", "completed", "failed", "needs_review", "rolled_back"):
            action = f"virtualmin_migration_{suffix}"
            with self.subTest(action=action):
                event = AuditEvent(
                    action=action,
                    content_type=content_type,
                    object_id=str(self.account.pk),
                    actor_type="system",
                )
                event.full_clean()
