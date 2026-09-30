"""A registrar webhook handler must not half-apply, and must not call the provider first.

`_handle_domain_expired` and its two siblings change `Domain.status`, then write an audit
event. Without an enclosing transaction the status save commits on its own, which fires
the `post_save` receiver whose `transaction.on_commit` therefore runs the Virtualmin call
IMMEDIATELY — before the audit row exists. If the audit write then fails, the panel has
been mutated for a change that has no audit trail, and ADR-0016's stated guarantee that a
signal's audit event rolls back with its save does not hold.

Adding `@transaction.atomic` alone does NOT fix this. Each handler catches its own
exceptions and returns `(False, reason)`, so no exception escapes the atomic block and
Django commits anyway — the same "returning an error inside atomic still commits" trap
this codebase has hit repeatedly. The handler must mark the transaction for rollback
before returning the failure.

The provider assertions run inside `captureOnCommitCallbacks(execute=True)`. Without it
`on_commit` never fires under `TestCase` at all, so "the provider was not called" would
pass vacuously. With it, a callback registered inside a savepoint that rolled back is
discarded by Django and a surviving one executes, so both directions are real.
"""

from __future__ import annotations

import ast
import inspect
from unittest.mock import patch

from django.test import TestCase

from apps.customers.models import Customer
from apps.domains import webhooks
from apps.domains.models import TLD, Domain, Registrar, TLDRegistrarAssignment
from apps.domains.webhooks import RegistrarWebhookView


class _AuditUnavailableError(Exception):
    """Distinct marker so a failing audit write is unambiguous."""


def _fail_only_the_webhook_audit(*args: object, **kwargs: object) -> None:
    """Break the handler's own audit write and nothing else.

    Patching `DomainsAuditService.log_domain_event` outright also breaks the audit calls
    the status-change signal makes, so the signal aborts before registering its
    post-commit hook and "the provider was not called" passes for entirely the wrong
    reason. Narrowing to this one event type keeps the signal path intact, which is what
    makes the provider assertion mean anything.
    """
    if kwargs.get("event_type") == "domain_expired_webhook":
        raise _AuditUnavailableError("audit store down")


class WebhookHandlerAtomicityTests(TestCase):
    def setUp(self) -> None:
        self.tld = TLD.objects.create(
            extension="ro",
            description=".ro",
            registration_price_cents=2300,
            renewal_price_cents=2300,
            transfer_price_cents=2300,
            min_registration_period=1,
            max_registration_period=10,
            is_active=True,
        )
        self.registrar = Registrar.objects.create(
            name="atomicity-registrar",
            display_name="Atomicity Registrar",
            website_url="https://example.test",
            status="active",
        )
        TLDRegistrarAssignment.objects.create(tld=self.tld, registrar=self.registrar, is_primary=True)
        self.customer = Customer.objects.create(
            name="Atomicity Customer",
            company_name="Atomicity SRL",
            customer_type="company",
            primary_email="atomicity@example.test",
        )
        self.domain = Domain.objects.create(
            name="webhook-atomicity.ro",
            tld=self.tld,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
        )
        self.view = RegistrarWebhookView()


    def test_a_failed_audit_write_leaves_the_domain_unchanged(self) -> None:
        """The status change and its audit event are one unit, or neither happened."""
        with (
            patch(
                "apps.domains.webhooks.DomainsAuditService.log_domain_event",
                side_effect=_fail_only_the_webhook_audit,
            ),
            patch("apps.domains.signals.sync_domain_to_virtualmin"),
            self.captureOnCommitCallbacks(execute=True),
        ):
            ok, _reason = self.view._handle_domain_expired(self.domain, {}, "198.51.100.7")

        self.assertFalse(ok, "the handler must report failure when it could not audit")
        self.domain.refresh_from_db()
        self.assertEqual(
            self.domain.status,
            "active",
            "the status change committed even though its audit event did not",
        )

    def test_the_provider_is_not_called_when_the_handler_fails(self) -> None:
        """A provider mutation for a change that did not survive is the expensive half.

        Asserted separately from the status check: a fix that rolls back the row but
        still reaches the panel leaves the panel diverged from the database, which is
        the divergence the whole post-commit deferral exists to prevent.
        """
        with (
            patch(
                "apps.domains.webhooks.DomainsAuditService.log_domain_event",
                side_effect=_fail_only_the_webhook_audit,
            ),
            patch("apps.domains.signals.sync_domain_to_virtualmin") as sync,
            self.captureOnCommitCallbacks(execute=True),
        ):
            self.view._handle_domain_expired(self.domain, {}, "198.51.100.7")

        sync.assert_not_called()

    def test_the_happy_path_still_expires_and_still_reaches_the_provider(self) -> None:
        """Guards against 'fixing' the failure case by breaking the feature.

        Without this, rolling back unconditionally — or never calling the provider at
        all — would satisfy both assertions above.
        """
        with (
            patch("apps.domains.signals.sync_domain_to_virtualmin") as sync,
            self.captureOnCommitCallbacks(execute=True),
        ):
            ok, _reason = self.view._handle_domain_expired(self.domain, {}, "198.51.100.7")

        self.assertTrue(ok)
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.status, "expired")
        sync.assert_called_once()
        self.assertEqual(sync.call_args.args[0].pk, self.domain.pk)


class WebhookSiblingHandlersShareTheShapeTests(TestCase):
    """The same unit-of-work rule applies to every handler that writes then audits.

    Recorded as its own test because the two handlers already carrying
    `@transaction.atomic` have the identical swallow-and-return-False shape, so the
    decorator alone never protected them either. Fixing only the three that lacked a
    decorator would leave the same defect in the two that had one.
    """

    def test_every_status_changing_handler_marks_rollback_before_returning_failure(self) -> None:
        source = inspect.getsource(webhooks)
        tree = ast.parse(source)

        handlers = {
            "_handle_domain_registered",
            "_handle_domain_renewed",
            "_handle_domain_transfer_completed",
            "_handle_domain_expired",
            "_handle_domain_suspended",
        }
        found: set[str] = set()
        unguarded: list[str] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name not in handlers:
                continue
            found.add(node.name)

            decorated = any(
                isinstance(d, ast.Attribute) and d.attr == "atomic" for d in node.decorator_list
            )
            marks_rollback = any(
                isinstance(sub, ast.Call)
                and getattr(sub.func, "attr", None) == "set_rollback"
                for sub in ast.walk(node)
            )
            if not (decorated and marks_rollback):
                unguarded.append(f"{node.name}(atomic={decorated}, set_rollback={marks_rollback})")

        # Count assertion, not a bare loop: a renamed or newly added handler must force a
        # conscious update here rather than silently shrinking what this test covers.
        self.assertEqual(found, handlers, "the handler set changed; update this contract deliberately")
        self.assertEqual(
            unguarded,
            [],
            "these handlers write then audit without a transaction that rolls back on failure: "
            + ", ".join(unguarded),
        )
