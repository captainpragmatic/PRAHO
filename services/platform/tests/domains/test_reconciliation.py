"""Durable reconciliation coverage for domains and submitted operations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from django.test import TestCase
from django_q.models import Schedule

from apps.common.types import Err, Ok, Result
from apps.customers.models import Customer
from apps.domains.gateways import DomainInfoResult, RegistrarAPIError, RegistrarNotFoundError
from apps.domains.models import TLD, Domain, DomainOperation, Registrar
from apps.domains.services import (
    RECONCILE_BATCH_LIMIT,
    DomainReconciliationService,
    DomainReconciliationSummary,
)

type GatewayResponse = Result[DomainInfoResult, RegistrarAPIError] | Exception


class StubGateway:
    """Programmable registrar-info gateway used by reconciliation tests."""

    def __init__(
        self,
        responses: dict[str, GatewayResponse],
        *,
        on_call: Callable[[str], None] | None = None,
    ) -> None:
        self.responses = responses
        self.on_call = on_call
        self.calls: list[str] = []

    def get_domain_info(self, domain_name: str) -> Result[DomainInfoResult, RegistrarAPIError]:
        self.calls.append(domain_name)
        if self.on_call is not None:
            self.on_call(domain_name)

        response = self.responses[domain_name]
        if isinstance(response, Exception):
            raise response
        return response


class DomainReconciliationTests(TestCase):
    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)

    def setUp(self) -> None:
        self.tld = TLD.objects.create(
            extension="example",
            description=".example",
            registration_price_cents=1000,
            renewal_price_cents=900,
            transfer_price_cents=800,
            grace_period_days=30,
        )
        self.registrar = Registrar.objects.create(
            name="reconciliation-registrar",
            display_name="Reconciliation Registrar",
            website_url="https://registrar.example.test",
            api_endpoint="https://api.registrar.example.test",
        )
        self.customer = Customer.objects.create(
            name="Reconciliation Customer",
            company_name="Reconciliation Customer SRL",
            customer_type="company",
            primary_email="domains@example.test",
        )

    def _domain(
        self,
        name: str,
        *,
        active: bool = False,
        expires_at: datetime | None = None,
        nameservers: list[str] | None = None,
        locked: bool = True,
    ) -> Domain:
        domain = Domain.objects.create(
            name=name,
            tld=self.tld,
            registrar=self.registrar,
            customer=self.customer,
            expires_at=expires_at,
            nameservers=nameservers or [],
            locked=locked,
        )
        if active:
            domain.activate()
            domain.save()
        return domain

    def _age_domain(self, domain: Domain, age: timedelta) -> None:
        Domain.objects.filter(pk=domain.pk).update(created_at=self.now - age)

    def _submitted_operation(
        self,
        domain: Domain,
        operation_type: str,
        parameters: dict[str, object],
        *,
        age: timedelta = timedelta(hours=1),
    ) -> DomainOperation:
        operation = DomainOperation.objects.create(
            domain=domain,
            registrar=self.registrar,
            operation_type=operation_type,
            parameters=parameters,
        )
        operation.mark_submitted(registrar_operation_id=f"operation-{operation.pk}")
        operation.save(
            update_fields=[
                "state",
                "registrar_operation_id",
                "submitted_at",
                "updated_at",
            ]
        )
        DomainOperation.objects.filter(pk=operation.pk).update(submitted_at=self.now - age)
        operation.refresh_from_db()
        return operation

    def _info(  # noqa: PLR0913  # keyword-only fixture builder
        self,
        domain_name: str,
        *,
        expires_at: datetime | None,
        registrar_domain_id: str = "REG-123",
        nameservers: list[str] | None = None,
        locked: bool = True,
        epp_code: str = "",
    ) -> DomainInfoResult:
        return DomainInfoResult(
            registrar_domain_id=registrar_domain_id,
            domain_name=domain_name,
            status="active",
            expires_at=expires_at,
            nameservers=nameservers or [],
            locked=locked,
            epp_code=epp_code,
        )

    def _run(self, gateway: StubGateway) -> DomainReconciliationSummary:
        with (
            patch("apps.domains.services.timezone.now", return_value=self.now),
            patch(
                "apps.domains.gateways.RegistrarGatewayFactory.create_gateway",
                return_value=gateway,
            ),
        ):
            return DomainReconciliationService.reconcile()

    def test_pending_registration_with_expiry_is_activated_and_operation_completed(self) -> None:
        domain = self._domain("pending.example")
        self._age_domain(domain, timedelta(hours=1))
        operation = self._submitted_operation(domain, "register", {"years": 1})
        expiry = self.now + timedelta(days=365)
        gateway = StubGateway(
            {
                domain.name: Ok(
                    self._info(
                        domain.name,
                        expires_at=expiry,
                        registrar_domain_id="REG-PENDING",
                        nameservers=["ns1.example.test", "ns2.example.test"],
                        epp_code="SECRET-EPP",
                    )
                )
            }
        )

        result = self._run(gateway)

        domain.refresh_from_db()
        operation.refresh_from_db()
        self.assertEqual(result["activated"], 1)
        self.assertEqual(domain.status, "active")
        self.assertEqual(domain.registrar_domain_id, "REG-PENDING")
        self.assertEqual(domain.expires_at, expiry)
        self.assertEqual(domain.nameservers, ["ns1.example.test", "ns2.example.test"])
        self.assertEqual(domain.get_decrypted_epp_code(), "SECRET-EPP")
        self.assertIsNotNone(domain.registered_at)
        self.assertEqual(operation.state, "completed")
        self.assertEqual(operation.result, {"reconciled": True})

    def test_pending_registration_younger_than_grace_is_untouched(self) -> None:
        domain = self._domain("young.example")
        self._age_domain(domain, timedelta(minutes=14))
        gateway = StubGateway({})

        with (
            patch("apps.domains.services.timezone.now", return_value=self.now),
            patch(
                "apps.domains.gateways.RegistrarGatewayFactory.create_gateway"
            ) as gateway_factory,
        ):
            result = DomainReconciliationService.reconcile()

        domain.refresh_from_db()
        self.assertEqual(domain.status, "pending")
        self.assertEqual(result["activated"], 0)
        gateway_factory.assert_not_called()
        self.assertEqual(gateway.calls, [])

    def test_not_found_registration_is_kept_before_24h_and_removed_after_24h(self) -> None:
        domain = self._domain("absent.example")
        self._age_domain(domain, timedelta(hours=23))
        gateway = StubGateway(
            {
                domain.name: Err(
                    RegistrarNotFoundError(domain.name, self.registrar.name)
                )
            }
        )

        with patch("apps.audit.services.AuditService.log_simple_event") as audit_log:
            first = self._run(gateway)
            self.assertTrue(Domain.objects.filter(pk=domain.pk).exists())
            self.assertEqual(first["awaiting"], 1)
            audit_log.assert_not_called()

            Domain.objects.filter(pk=domain.pk).update(
                created_at=self.now - timedelta(hours=25)
            )
            second = self._run(gateway)

        self.assertFalse(Domain.objects.filter(pk=domain.pk).exists())
        self.assertEqual(second["removed"], 1)
        # The delete also fires the post_delete security signal (domain_deleted) —
        # that second audit event is desired; assert the reconciliation event exists.
        reconciled_calls = [
            call
            for call in audit_log.call_args_list
            if call.args and call.args[0] == "domain_registration_reconciled_absent"
        ]
        self.assertEqual(len(reconciled_calls), 1)
        self.assertEqual(
            reconciled_calls[0].kwargs["metadata"],
            {
                "domain_name": "absent.example",
                "customer_id": str(self.customer.pk),
            },
        )

    def test_transfer_not_found_after_24h_is_never_deleted(self) -> None:
        domain = self._domain("transfer-missing.example")
        domain.start_transfer_in()
        domain.save()
        self._age_domain(domain, timedelta(days=4))
        operation = self._submitted_operation(domain, "transfer_in", {"epp_code": "***"})
        gateway = StubGateway(
            {
                domain.name: Err(
                    RegistrarNotFoundError(domain.name, self.registrar.name)
                )
            }
        )

        result = self._run(gateway)

        domain.refresh_from_db()
        operation.refresh_from_db()
        self.assertEqual(result["awaiting"], 1)
        self.assertEqual(domain.status, "transfer_in")
        self.assertEqual(operation.state, "submitted")

    def test_transfer_with_expiry_is_activated(self) -> None:
        domain = self._domain("transfer-complete.example")
        domain.start_transfer_in()
        domain.save()
        self._age_domain(domain, timedelta(hours=2))
        operation = self._submitted_operation(domain, "transfer_in", {"epp_code": "***"})
        expiry = self.now + timedelta(days=365)
        gateway = StubGateway(
            {
                domain.name: Ok(
                    self._info(
                        domain.name,
                        expires_at=expiry,
                        registrar_domain_id="REG-TRANSFER",
                    )
                )
            }
        )

        result = self._run(gateway)

        domain.refresh_from_db()
        operation.refresh_from_db()
        self.assertEqual(result["activated"], 1)
        self.assertEqual(domain.status, "active")
        self.assertEqual(domain.registrar_domain_id, "REG-TRANSFER")
        self.assertEqual(domain.expires_at, expiry)
        self.assertEqual(operation.state, "completed")

    def test_renewal_completes_only_when_expiry_advances(self) -> None:
        previous_expiry = self.now + timedelta(days=60)
        renewed_domain = self._domain(
            "renewed.example",
            active=True,
            expires_at=previous_expiry,
        )
        unchanged_domain = self._domain(
            "renew-unchanged.example",
            active=True,
            expires_at=previous_expiry,
        )
        renewed_domain.renewal_notices_sent = 30
        renewed_domain.save(update_fields=["renewal_notices_sent", "updated_at"])
        renewed_operation = self._submitted_operation(
            renewed_domain,
            "renew",
            {
                "years": 1,
                "prev_expires_at": previous_expiry.isoformat(),
            },
        )
        unchanged_operation = self._submitted_operation(
            unchanged_domain,
            "renew",
            {
                "years": 1,
                "prev_expires_at": previous_expiry.isoformat(),
            },
        )
        new_expiry = previous_expiry + timedelta(days=365)
        gateway = StubGateway(
            {
                renewed_domain.name: Ok(
                    self._info(renewed_domain.name, expires_at=new_expiry)
                ),
                unchanged_domain.name: Ok(
                    self._info(unchanged_domain.name, expires_at=previous_expiry)
                ),
            }
        )

        result = self._run(gateway)

        renewed_domain.refresh_from_db()
        unchanged_domain.refresh_from_db()
        renewed_operation.refresh_from_db()
        unchanged_operation.refresh_from_db()
        self.assertEqual(result["completed"], 1)
        self.assertEqual(renewed_domain.expires_at, new_expiry)
        self.assertEqual(renewed_domain.renewal_notices_sent, 0)
        self.assertEqual(renewed_operation.state, "completed")
        self.assertEqual(
            renewed_operation.result,
            {"new_expires_at": new_expiry.isoformat()},
        )
        self.assertEqual(unchanged_domain.expires_at, previous_expiry)
        self.assertEqual(unchanged_operation.state, "submitted")

    def test_nameserver_update_completes_only_when_sets_match(self) -> None:
        original = ["old-ns.example.test"]
        requested = ["ns1.example.test", "ns2.example.test"]
        matched_domain = self._domain(
            "nameservers-match.example",
            active=True,
            expires_at=self.now + timedelta(days=365),
            nameservers=original,
        )
        mismatched_domain = self._domain(
            "nameservers-mismatch.example",
            active=True,
            expires_at=self.now + timedelta(days=365),
            nameservers=original,
        )
        matched_operation = self._submitted_operation(
            matched_domain,
            "nameserver_update",
            {"nameservers": requested},
        )
        mismatched_operation = self._submitted_operation(
            mismatched_domain,
            "nameserver_update",
            {"nameservers": requested},
        )
        gateway = StubGateway(
            {
                matched_domain.name: Ok(
                    self._info(
                        matched_domain.name,
                        expires_at=matched_domain.expires_at,
                        nameservers=list(reversed(requested)),
                    )
                ),
                mismatched_domain.name: Ok(
                    self._info(
                        mismatched_domain.name,
                        expires_at=mismatched_domain.expires_at,
                        nameservers=["different.example.test"],
                    )
                ),
            }
        )

        result = self._run(gateway)

        matched_domain.refresh_from_db()
        mismatched_domain.refresh_from_db()
        matched_operation.refresh_from_db()
        mismatched_operation.refresh_from_db()
        self.assertEqual(result["completed"], 1)
        self.assertEqual(matched_domain.nameservers, requested)
        self.assertEqual(matched_operation.state, "completed")
        self.assertEqual(mismatched_domain.nameservers, original)
        self.assertEqual(mismatched_operation.state, "submitted")

    def test_lock_update_completes_only_when_value_matches(self) -> None:
        matched_domain = self._domain(
            "lock-match.example",
            active=True,
            expires_at=self.now + timedelta(days=365),
            locked=True,
        )
        mismatched_domain = self._domain(
            "lock-mismatch.example",
            active=True,
            expires_at=self.now + timedelta(days=365),
            locked=True,
        )
        matched_operation = self._submitted_operation(
            matched_domain,
            "lock_update",
            {"locked": False},
        )
        mismatched_operation = self._submitted_operation(
            mismatched_domain,
            "lock_update",
            {"locked": False},
        )
        gateway = StubGateway(
            {
                matched_domain.name: Ok(
                    self._info(
                        matched_domain.name,
                        expires_at=matched_domain.expires_at,
                        locked=False,
                    )
                ),
                mismatched_domain.name: Ok(
                    self._info(
                        mismatched_domain.name,
                        expires_at=mismatched_domain.expires_at,
                        locked=True,
                    )
                ),
            }
        )

        result = self._run(gateway)

        matched_domain.refresh_from_db()
        mismatched_domain.refresh_from_db()
        matched_operation.refresh_from_db()
        mismatched_operation.refresh_from_db()
        self.assertEqual(result["completed"], 1)
        self.assertFalse(matched_domain.locked)
        self.assertEqual(matched_operation.state, "completed")
        self.assertTrue(mismatched_domain.locked)
        self.assertEqual(mismatched_operation.state, "submitted")

    def test_one_expiry_advance_completes_only_one_renewal_intent(self) -> None:
        """Two pending renewals sharing one prev-expiry snapshot must not BOTH be
        completed by a single registrar extension — only the oldest is proven;
        the second stays submitted (and fails visibly at 72h if never proven)."""
        previous_expiry = self.now + timedelta(days=60)
        domain = self._domain("double-intent.example", active=True, expires_at=previous_expiry)
        first_op = self._submitted_operation(
            domain,
            "renew",
            {"years": 1, "prev_expires_at": previous_expiry.isoformat()},
            age=timedelta(hours=3),
        )
        second_op = self._submitted_operation(
            domain,
            "renew",
            {"years": 1, "prev_expires_at": previous_expiry.isoformat()},
            age=timedelta(hours=2),
        )
        new_expiry = previous_expiry + timedelta(days=365)
        gateway = StubGateway({domain.name: Ok(self._info(domain.name, expires_at=new_expiry))})

        result = self._run(gateway)

        first_op.refresh_from_db()
        second_op.refresh_from_db()
        self.assertEqual(result["completed"], 1)
        self.assertEqual(first_op.state, "completed")
        self.assertEqual(second_op.state, "submitted")

    def test_accepted_registration_is_not_deleted_on_not_found(self) -> None:
        """A submitted register op WITH an operation handle proves the registrar
        ACCEPTED the request — a slow async registration absent from the info
        endpoint past 24h must not be deleted out from under a paid customer."""
        domain = self._domain("accepted-slow.example")
        self._age_domain(domain, timedelta(hours=30))
        operation = self._submitted_operation(domain, "register", {"years": 1})
        gateway = StubGateway(
            {domain.name: Err(RegistrarNotFoundError(domain.name, self.registrar.name))}
        )

        result = self._run(gateway)

        self.assertTrue(Domain.objects.filter(pk=domain.pk).exists())
        operation.refresh_from_db()
        self.assertEqual(operation.state, "submitted")
        self.assertEqual(result["removed"], 0)
        self.assertEqual(result["awaiting"], 1)

    def test_webhook_activated_domain_completes_its_stranded_register_operation(self) -> None:
        """A registration webhook activates the Domain without touching the
        submitted operation — the reconciler must complete it, or it stays
        submitted forever (invisible to the pending-domain phase)."""
        domain = self._domain("webhook-won.example", active=True, expires_at=self.now + timedelta(days=365))
        operation = self._submitted_operation(domain, "register", {"years": 1})
        gateway = StubGateway(
            {domain.name: Ok(self._info(domain.name, expires_at=domain.expires_at))}
        )

        result = self._run(gateway)

        operation.refresh_from_db()
        self.assertEqual(operation.state, "completed")
        self.assertEqual(result["completed"], 1)

    def test_skip_class_rows_do_not_starve_newer_pending_rows(self) -> None:
        """Rows whose registrar has no gateway must not consume the batch cap —
        otherwise 50 misconfigured rows starve every newer pending registration
        on every hourly run, forever."""
        bad_registrar = Registrar.objects.create(
            name="no-gateway-registrar",
            display_name="No Gateway",
            website_url="https://none.example.test",
            api_endpoint="https://api.none.example.test",
        )
        for index in range(RECONCILE_BATCH_LIMIT):
            domain = Domain.objects.create(
                name=f"stuck-{index:03d}.example",
                tld=self.tld,
                registrar=bad_registrar,
                customer=self.customer,
            )
            self._age_domain(domain, timedelta(hours=10))
        fresh = self._domain("fresh-behind-the-wall.example")
        self._age_domain(fresh, timedelta(hours=1))
        expiry = self.now + timedelta(days=365)
        stub = StubGateway({fresh.name: Ok(self._info(fresh.name, expires_at=expiry))})

        def _factory(registrar: Registrar) -> StubGateway:
            if registrar.pk == bad_registrar.pk:
                raise ValueError(f"No gateway registered for registrar: {registrar.name}")
            return stub

        with (
            patch("apps.domains.services.timezone.now", return_value=self.now),
            patch(
                "apps.domains.gateways.RegistrarGatewayFactory.create_gateway",
                side_effect=_factory,
            ),
        ):
            result = DomainReconciliationService.reconcile()

        fresh.refresh_from_db()
        self.assertEqual(fresh.status, "active")
        self.assertEqual(result["activated"], 1)

    def test_renewal_without_recorded_prev_expiry_is_not_completed(self) -> None:
        """prev_expires_at is the reconciliation PROOF — a renew op missing it
        (manual/ORM-created) must not be completed on any non-null expiry."""
        expiry = self.now + timedelta(days=60)
        domain = self._domain("no-proof.example", active=True, expires_at=expiry)
        operation = self._submitted_operation(domain, "renew", {"years": 1})
        gateway = StubGateway({domain.name: Ok(self._info(domain.name, expires_at=expiry))})

        result = self._run(gateway)

        domain.refresh_from_db()
        operation.refresh_from_db()
        self.assertEqual(result["completed"], 0)
        self.assertEqual(operation.state, "submitted")
        self.assertEqual(domain.expires_at, expiry)

    def test_operation_older_than_72h_fails_without_changing_domain(self) -> None:
        previous_expiry = self.now + timedelta(days=30)
        domain = self._domain(
            "stale-renewal.example",
            active=True,
            expires_at=previous_expiry,
        )
        domain.renewal_notices_sent = 14
        domain.save(update_fields=["renewal_notices_sent", "updated_at"])
        operation = self._submitted_operation(
            domain,
            "renew",
            {
                "years": 1,
                "prev_expires_at": previous_expiry.isoformat(),
            },
            age=timedelta(hours=73),
        )
        gateway = StubGateway(
            {
                domain.name: Ok(
                    self._info(domain.name, expires_at=previous_expiry)
                )
            }
        )

        result = self._run(gateway)

        domain.refresh_from_db()
        operation.refresh_from_db()
        self.assertEqual(result["failed"], 1)
        self.assertEqual(domain.expires_at, previous_expiry)
        self.assertEqual(domain.renewal_notices_sent, 14)
        self.assertEqual(operation.state, "failed")
        self.assertEqual(
            operation.error_message,
            "unconfirmed after 72h — investigate at the registrar",
        )

    def test_one_row_crash_does_not_stop_the_next_row(self) -> None:
        crashing = self._domain("a-crashing.example")
        succeeding = self._domain("b-succeeding.example")
        self._age_domain(crashing, timedelta(hours=2))
        self._age_domain(succeeding, timedelta(hours=1))
        expiry = self.now + timedelta(days=365)
        gateway = StubGateway(
            {
                crashing.name: RuntimeError("registrar adapter crashed"),
                succeeding.name: Ok(
                    self._info(succeeding.name, expires_at=expiry)
                ),
            }
        )

        result = self._run(gateway)

        crashing.refresh_from_db()
        succeeding.refresh_from_db()
        self.assertEqual(result["errors"], 1)
        self.assertFalse(result["success"])
        self.assertEqual(result["activated"], 1)
        self.assertEqual(crashing.status, "pending")
        self.assertEqual(succeeding.status, "active")
        self.assertEqual(gateway.calls, [crashing.name, succeeding.name])

    def test_pending_registration_batch_is_capped(self) -> None:
        responses: dict[str, GatewayResponse] = {}
        for index in range(RECONCILE_BATCH_LIMIT + 1):
            domain = self._domain(f"batch-{index:03d}.example")
            self._age_domain(domain, timedelta(hours=1))
            responses[domain.name] = Ok(
                self._info(domain.name, expires_at=None)
            )
        gateway = StubGateway(responses)

        result = self._run(gateway)

        self.assertEqual(len(gateway.calls), RECONCILE_BATCH_LIMIT)
        self.assertEqual(result["unconfirmed"], RECONCILE_BATCH_LIMIT)
        self.assertEqual(
            Domain.objects.filter(status="pending").count(),
            RECONCILE_BATCH_LIMIT + 1,
        )

    def test_schedule_setup_creates_both_schedules_idempotently(self) -> None:
        from apps.domains.tasks import setup_domain_scheduled_tasks  # noqa: PLC0415

        Schedule.objects.filter(
            name__in=("domains-renewal-notices", "domains-reconcile-pending")
        ).delete()

        first = setup_domain_scheduled_tasks()
        second = setup_domain_scheduled_tasks()

        self.assertEqual(
            first,
            {
                "renewal_notices": "created",
                "reconcile_pending": "created",
            },
        )
        self.assertEqual(
            second,
            {
                "renewal_notices": "already_exists",
                "reconcile_pending": "already_exists",
            },
        )
        renewal_schedule = Schedule.objects.get(name="domains-renewal-notices")
        reconciliation_schedule = Schedule.objects.get(
            name="domains-reconcile-pending"
        )
        self.assertEqual(renewal_schedule.schedule_type, Schedule.DAILY)
        self.assertEqual(
            renewal_schedule.func,
            "apps.domains.tasks.process_domain_renewal_notices",
        )
        self.assertEqual(
            reconciliation_schedule.schedule_type,
            Schedule.HOURLY,
        )
        self.assertEqual(
            reconciliation_schedule.func,
            "apps.domains.tasks.reconcile_pending_domain_operations",
        )

    def test_concurrent_activation_is_not_double_applied(self) -> None:
        domain = self._domain("concurrent.example")
        self._age_domain(domain, timedelta(hours=1))
        operation = self._submitted_operation(domain, "register", {"years": 1})
        concurrent_expiry = self.now + timedelta(days=200)

        def activate_during_read(_domain_name: str) -> None:
            concurrent = Domain.objects.get(pk=domain.pk)
            concurrent.registrar_domain_id = "CONCURRENT-ID"
            concurrent.expires_at = concurrent_expiry
            concurrent.nameservers = ["concurrent-ns.example.test"]
            concurrent.registered_at = self.now
            concurrent.activate()
            concurrent.save()

        gateway = StubGateway(
            {
                domain.name: Ok(
                    self._info(
                        domain.name,
                        expires_at=self.now + timedelta(days=400),
                        registrar_domain_id="RECONCILER-ID",
                        nameservers=["reconciler-ns.example.test"],
                    )
                )
            },
            on_call=activate_during_read,
        )

        result = self._run(gateway)

        domain.refresh_from_db()
        operation.refresh_from_db()
        self.assertEqual(result["activated"], 0)
        self.assertEqual(result["errors"], 0)
        self.assertEqual(domain.status, "active")
        self.assertEqual(domain.registrar_domain_id, "CONCURRENT-ID")
        self.assertEqual(domain.expires_at, concurrent_expiry)
        self.assertEqual(domain.nameservers, ["concurrent-ns.example.test"])
        self.assertEqual(operation.state, "completed")

    def test_expiry_sweep_respects_exact_tld_grace_boundary(self) -> None:
        exactly_at_boundary = self._domain(
            "expiry-boundary.example",
            active=True,
            expires_at=self.now - timedelta(days=30),
        )
        one_day_inside = self._domain(
            "expiry-inside.example",
            active=True,
            expires_at=self.now - timedelta(days=29),
        )
        one_day_past = self._domain(
            "expiry-past.example",
            active=True,
            expires_at=self.now - timedelta(days=31),
        )
        gateway = StubGateway({})

        result = self._run(gateway)

        exactly_at_boundary.refresh_from_db()
        one_day_inside.refresh_from_db()
        one_day_past.refresh_from_db()
        self.assertEqual(result["expired"], 1)
        self.assertEqual(exactly_at_boundary.status, "active")
        self.assertEqual(one_day_inside.status, "active")
        self.assertEqual(one_day_past.status, "expired")
