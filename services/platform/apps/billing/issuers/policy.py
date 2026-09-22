"""Which system owns a document, and therefore who may file it with ANAF.

The load-bearing invariant of the whole integration is: **one authoritative
invoice, one authoritative number, one e-Factura submission owner.** PRAHO's own
e-Factura stack stays in the repository after an external issuer is switched on,
so nothing but an explicit guard stops it from submitting a document the provider
has already filed. Two uploads of the same invoice to SPV is the failure this
module exists to make impossible.

The decision is taken per document, never from a global setting. `issuer_provider`
is stamped at creation and frozen into the fiscal snapshot, so a built-in invoice
issued before the switch keeps submitting through PRAHO forever, and a worker that
already loaded an invoice cannot have the answer change underneath it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from apps.billing.invoice_models import ISSUER_BUILTIN
from apps.common.types import Err, Ok, Result

from .base import InvoiceIssuerGateway, get_invoice_issuer, get_registered_issuers

if TYPE_CHECKING:
    from apps.billing.invoice_models import Invoice

logger = logging.getLogger(__name__)


class EFacturaProviderConflictError(RuntimeError):
    """Raised when something tries to file a document PRAHO does not own.

    This is a backstop, not a control-flow signal. Callers are expected to check
    `efactura_submission_denied_reason` first and decline cleanly; reaching this
    exception means a code path bypassed that check.
    """


def efactura_submission_denied_reason(invoice: Invoice) -> str | None:
    """Return why this invoice must not reach SPV from PRAHO, or None if it may.

    Returns a reason string rather than a bool so the caller can log, audit and
    surface *why* without restating the policy.
    """
    if invoice.issuer_provider != ISSUER_BUILTIN:
        return (
            f"e-Factura submission is owned by the issuing provider "
            f"({invoice.issuer_provider!r}); PRAHO must not file this document."
        )
    return None


def assert_efactura_submission_allowed(invoice: Invoice) -> None:
    """Fail closed immediately before an SPV-mutating call.

    Placed at the lowest boundary that still knows which invoice is being filed,
    so no caller — view, task, scheduled poller or signal — can route around it.
    """
    reason = efactura_submission_denied_reason(invoice)
    if reason is not None:
        raise EFacturaProviderConflictError(reason)


def resolve_issuer(invoice: Invoice) -> InvoiceIssuerGateway:
    """Return the gateway that owns this document.

    Resolved from the document's own stamped provenance, never from a global
    "current provider" setting. That is what lets a built-in invoice issued before
    a switch keep behaving like a built-in invoice forever.
    """
    return get_invoice_issuer(invoice.issuer_provider)


def default_issuer_provider() -> str:
    """Which provider a NEW document should be stamped with.

    The one place a global setting legitimately applies: choosing an issuer for a
    document that does not exist yet. Once stamped it is frozen, so flipping this
    never reaches a document already created.

    An unrecognised value falls back to the built-in issuer rather than raising,
    because this runs inside the transaction that converges a customer payment: a
    mistyped setting must not turn someone's payment into a 500. The fallback is
    therefore not the defence. The defence is that the settings write path refuses
    to persist a value that is not a registered issuer, so reaching this line with
    an unknown provider means the value arrived out of band (a direct database
    write, or a Django-settings override) and warrants the alarm it raises.
    """
    from apps.settings.services import SettingsService  # noqa: PLC0415

    configured = str(SettingsService.get_setting("billing.invoice_issuer", ISSUER_BUILTIN) or ISSUER_BUILTIN)
    if configured in get_registered_issuers():
        return configured

    logger.error(
        f"🔥 [Issuer] Configured invoice issuer {configured!r} is not registered; "
        f"stamping {ISSUER_BUILTIN!r} instead. New documents are being numbered by "
        f"PRAHO's own sequence, which is a fiscal act - check billing.invoice_issuer."
    )
    return ISSUER_BUILTIN


def operator_safe_detail(error: object) -> str:
    """A provider error reduced to something safe to show an operator.

    Provider errors reach staff-facing responses, and SmartBill's carry HTML aimed
    at its own web UI plus occasional internals from an HTML 500. Cutting at the
    first tag keeps the human cause and drops the markup; the length cap stops a
    stack trace or an error page from being rendered as a message.
    """
    from .smartbill.responses import first_sentence  # noqa: PLC0415

    cleaned = first_sentence(str(error))
    limit = 300
    return cleaned[: limit - 1] + "\u2026" if len(cleaned) > limit else cleaned


def issues_externally(provider: str) -> bool:
    """Whether issuance for this provider needs a network call.

    The built-in issuer allocates from a local sequence inside the caller's
    transaction; an external one cannot, which is why its number arrives later.
    """
    return provider != ISSUER_BUILTIN


@dataclass(frozen=True)
class SwitchBlocker:
    """One reason a provider switch must not happen right now."""

    reason: str
    detail: str


def can_switch_invoice_issuer(target: str, *, probe_provider: bool = True) -> Result[None, tuple[SwitchBlocker, ...]]:
    """Whether the issuer may be changed for NEW documents right now.

    The switch only ever affects documents that do not exist yet — provenance is
    frozen per document — so this is not about history. It is about work already in
    flight: an attempt whose outcome nobody knows yet, or a document the previous
    issuer is still responsible for filing with ANAF.

    Reversibility is partial by nature, and the UI should say so: turning SmartBill
    off does not un-issue anything it issued, and those documents still need its
    credentials for reversal and PDF retrieval.

    `probe_provider` controls the one check that leaves the machine. Callers running
    inside a transaction must pass False: holding row locks across a third-party HTTP
    call is bad on its own, and under a retrying atomic decorator the call would be
    re-issued on every attempt. Credential health is a point-in-time network fact
    rather than a transactional invariant, so the write path checks only durable
    state and leaves the probe to "Test connection" and to issuance itself, which
    already refuses and alerts rather than issuing against a broken account.
    """
    from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus  # noqa: PLC0415
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415

    from .models import IssuanceState, ProviderIssuance  # noqa: PLC0415

    blockers: list[SwitchBlocker] = []

    unresolved = ProviderIssuance.objects.filter(
        state__in=[IssuanceState.PENDING.value, IssuanceState.CLAIMED.value, IssuanceState.OUTCOME_UNKNOWN.value]
    ).count()
    if unresolved:
        blockers.append(
            SwitchBlocker(
                reason="Issuance attempts are unresolved",
                detail=(
                    f"{unresolved} attempt(s) are pending, claimed, or of unknown outcome. "
                    f"Switching now would leave work owned by a provider nobody is watching."
                ),
            )
        )

    awaiting = Invoice.objects.filter(number__isnull=True, status="draft").count()
    if awaiting:
        blockers.append(
            SwitchBlocker(
                reason="Invoices are awaiting a number",
                detail=f"{awaiting} invoice(s) have no legal number yet and are still expecting their issuer.",
            )
        )

    if issues_externally(target):
        in_flight = EFacturaDocument.objects.filter(
            status__in=[
                EFacturaStatus.QUEUED.value,
                EFacturaStatus.UPLOADING.value,
                EFacturaStatus.SUBMITTED.value,
                EFacturaStatus.PROCESSING.value,
                EFacturaStatus.OUTCOME_UNKNOWN.value,
            ]
        ).count()
        if in_flight:
            blockers.append(
                SwitchBlocker(
                    reason="e-Factura submissions are in flight",
                    detail=(
                        f"{in_flight} document(s) are mid-submission to ANAF. Handing e-Factura to a "
                        f"provider while PRAHO is still filing risks the same invoice reaching SPV twice."
                    ),
                )
            )

        if probe_provider:
            report = get_invoice_issuer(target).validate_configuration()
            if isinstance(report, Err):
                blockers.append(
                    SwitchBlocker(
                        reason=f"{target} is not usable yet",
                        detail=operator_safe_detail(report.error),
                    )
                )

    return Err(tuple(blockers)) if blockers else Ok(None)
