"""The contract an invoice issuer must satisfy.

Deliberately tiny. An issuer answers two questions: is it configured, and can it
turn a prepared document into a legally numbered invoice. Everything else PRAHO
already owns and keeps owning — proformas, payments, refunds, dunning, recurring
schedules, VAT decisions, PDF delivery, email and reporting. Putting any of those
on this interface would invite a provider to become the billing engine.

The load-bearing type is `IssueOutcome`. A provider call has three outcomes, not
two, and conflating the third with failure is how duplicate fiscal documents get
created: a timeout may mean the document was never issued, or that it was issued
and the response was lost. Only one of those is safe to retry.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from apps.common.types import Err, Result

if TYPE_CHECKING:
    from uuid import UUID

    from apps.billing.invoice_models import Invoice


@dataclass(frozen=True)
class Issued:
    """The provider assigned a legal number. Safe to record as authoritative.

    Identity contract, fixed here so two implementations cannot satisfy the types
    while storing incompatible things:

    * `number` is the provider's number component ("000001", or "3593").
    * `series` is the provider's series component when it has one ("FCT"), else "".
    * `legal_number` is what goes into `Invoice.number` and onto the document.

    The built-in issuer returns a already-composed number with an empty series,
    because its sequence formats the prefix itself.
    """

    number: str
    series: str = ""
    provider_document_id: str = ""
    response_digest: str = ""

    @property
    def legal_number(self) -> str:
        """The complete number as it appears on the document and in `Invoice.number`."""
        return f"{self.series}-{self.number}" if self.series else self.number


@dataclass(frozen=True)
class Rejected:
    """The provider refused, provably without creating anything.

    Safe to correct and retry: no fiscal number was consumed.
    """

    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class Ambiguous:
    """The outcome is unknown; a document MAY exist at the provider.

    Never retry automatically. A second attempt after a lost response is how one
    order becomes two legally numbered invoices, and an invoice that is not the
    last in its series can only be cancelled or reversed, never deleted.
    """

    reason: str


IssueOutcome = Issued | Rejected | Ambiguous


@dataclass(frozen=True)
class PreparedDocument:
    """Exactly what will be sent, frozen before anything is claimed or posted.

    Split out from submission because the durable attempt record must contain the
    real payload BEFORE the provider call. If the process dies mid-call, the only
    thread back is what we wrote down first — and "we sent something" is not enough
    for a human to identify a document at a provider offering no lookup.
    """

    payload: dict[str, Any]
    digest: str


@dataclass(frozen=True)
class ConfigurationReport:
    """What a 'Test connection' action reports back to an operator."""

    provider: str
    ok: bool
    checks: tuple[str, ...] = field(default_factory=tuple)
    problems: tuple[str, ...] = field(default_factory=tuple)


class InvoiceIssuerGateway(ABC):
    """Turns a prepared PRAHO invoice into a legally numbered document."""

    provider: str

    @abstractmethod
    def validate_configuration(self) -> Result[ConfigurationReport, str]:
        """Check credentials and account-coupled configuration without issuing anything."""

    @abstractmethod
    def prepare(self, invoice: Invoice) -> Result[PreparedDocument, tuple[str, ...]]:
        """Build the exact request, or return every reason it must not be sent.

        Pure and side-effect free: it must be safe to call before claiming, because
        the orchestrator stores the result durably first.
        """

    @abstractmethod
    def submit(self, prepared: PreparedDocument, *, attempt_id: UUID) -> IssueOutcome:
        """Send a previously prepared request.

        `attempt_id` identifies one attempt so an ambiguous outcome can be
        reconciled later against whatever evidence the provider exposes.

        MUST NOT be called inside a transaction (ADR-0045): an outer rollback would
        erase PRAHO's record of a document that exists at the provider.
        """

    def issue_invoice(self, invoice: Invoice, *, attempt_id: UUID) -> IssueOutcome:
        """Convenience for callers that do not keep a durable attempt record.

        Used by the built-in numbering path, where preparation cannot fail and no
        provider state can be orphaned.
        """
        prepared = self.prepare(invoice)
        if isinstance(prepared, Err):
            return Rejected(errors=tuple(prepared.error))
        return self.submit(prepared.unwrap(), attempt_id=attempt_id)


# =============================================================================
# Registry + factory
# =============================================================================

_ISSUER_REGISTRY: dict[str, type[InvoiceIssuerGateway]] = {}
"""Populated once at startup by each issuer module at import time.

Django's AppConfig.ready() runs single-threaded during startup and the registry is
read-only afterwards, so no lock is needed — the same convention as
``apps/infrastructure/cloud_gateway.py``.
"""


def register_invoice_issuer(provider: str, gateway_cls: type[InvoiceIssuerGateway]) -> None:
    """Register an issuer implementation for a provider key.

    Refuses a key that disagrees with the class, and refuses to replace an existing
    registration with a different class. Otherwise an import-order accident could
    silently substitute who issues a company's invoices — the same ownership
    protection `get_invoice_issuer` provides on the read side.

    Re-registering the identical class is allowed, so startup stays idempotent.
    """
    if provider != gateway_cls.provider:
        raise ValueError(
            f"Issuer key {provider!r} disagrees with {gateway_cls.__name__}.provider ({gateway_cls.provider!r})"
        )
    existing = _ISSUER_REGISTRY.get(provider)
    if existing is not None and existing is not gateway_cls:
        raise ValueError(
            f"Issuer {provider!r} is already registered to {existing.__name__}; "
            f"refusing to replace it with {gateway_cls.__name__}"
        )
    _ISSUER_REGISTRY[provider] = gateway_cls


def get_invoice_issuer(provider: str) -> InvoiceIssuerGateway:
    """Build the gateway for a provider key.

    Raises rather than falling back to a default: silently issuing through the
    wrong provider is worse than failing loudly.
    """
    gateway_cls = _ISSUER_REGISTRY.get(provider)
    if gateway_cls is None:
        available = ", ".join(sorted(_ISSUER_REGISTRY)) or "(none)"
        raise ValueError(f"Unknown invoice issuer: {provider!r}. Registered: {available}")
    return gateway_cls()


def get_registered_issuers() -> list[str]:
    return sorted(_ISSUER_REGISTRY)
