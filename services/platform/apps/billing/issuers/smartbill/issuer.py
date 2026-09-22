"""The SmartBill implementation of the issuer gateway.

Maps, posts, classifies. It deliberately does no orchestration: claims, retries and
reconciliation live in the issuance service, because those decisions depend on
durable state this object does not own.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

from django.utils import timezone

from apps.billing.efactura.settings import ro_local_date
from apps.billing.invoice_models import ISSUER_SMARTBILL
from apps.common.types import Err, Ok, Result

from ..base import (  # noqa: TID252  # Sibling package module
    Ambiguous,
    ConfigurationReport,
    InvoiceIssuerGateway,
    Issued,
    IssueOutcome,
    PreparedDocument,
    Rejected,
    register_invoice_issuer,
)
from .client import SmartBillClient, SmartBillCredentials
from .mapper import SmartBillAccountConfig, build_invoice_payload
from .responses import Verdict

if TYPE_CHECKING:
    from uuid import UUID

    from apps.billing.invoice_models import Invoice

logger = logging.getLogger(__name__)


def payload_digest(payload: dict[str, object]) -> str:
    """Stable hash of exactly what was sent, so tampering is detectable later."""
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


class SmartBillIssuer(InvoiceIssuerGateway):
    provider = ISSUER_SMARTBILL

    def __init__(
        self,
        client: SmartBillClient | None = None,
        config: SmartBillAccountConfig | None = None,
    ) -> None:
        self._config = config or _config_from_settings()
        self._client = client or SmartBillClient(_credentials_from_settings())

    def validate_configuration(self) -> Result[ConfigurationReport, str]:
        """Prove the account-coupled strings exist before anything is issued.

        `seriesName` and `taxName` must match the SmartBill account exactly, and a
        mismatch is only discovered when a document fails — or worse, succeeds with
        the wrong rate. This is the "Test connection" action's real work.
        """
        checks: list[str] = []
        problems: list[str] = []

        series = self._client.get_series()
        if series.verdict is Verdict.SUCCESS:
            names = {entry.get("name") for entry in (series.payload.get("list") or [])}
            if self._config.invoice_series in names:
                checks.append(f"Invoice series {self._config.invoice_series!r} exists")
            else:
                problems.append(
                    f"Invoice series {self._config.invoice_series!r} not found in the account "
                    f"(found: {sorted(n for n in names if n)})"
                )
        else:
            problems.append(f"Could not list series: {series.error_text}")

        taxes = self._client.get_tax_rates()
        if taxes.verdict is Verdict.SUCCESS:
            available = {entry.get("name") for entry in (taxes.payload.get("taxes") or [])}
            for key, name in self._config.tax_names.items():
                if name in available:
                    checks.append(f"Tax name {name!r} exists (for {key})")
                else:
                    problems.append(f"Tax name {name!r} (mapped from {key}) not found in the account")
        else:
            problems.append(f"Could not list VAT rates: {taxes.error_text}")

        report = ConfigurationReport(
            provider=self.provider,
            ok=not problems,
            checks=tuple(checks),
            problems=tuple(problems),
        )
        return Ok(report) if not problems else Err("; ".join(problems))

    def fetch_pdf(self, series: str, number: str) -> Result[bytes, str]:
        """The provider's own rendering: the document the customer actually gets."""
        return self._client.fetch_invoice_pdf(series, number)

    def prepare_storno(self, original: Invoice) -> Result[PreparedDocument, tuple[str, ...]]:
        """Reverse a SmartBill document by its series and number.

        The request carries no amounts: `/invoice/reverse` reverses the WHOLE
        document or nothing. A partial refund therefore has no representation here
        and is refused upstream rather than approximated by reversing too much.
        """
        issuance = getattr(original, "provider_issuance", None)
        problems: list[str] = []
        if issuance is None or not issuance.provider_number:
            problems.append("The original invoice has no SmartBill number to reverse")
        if problems:
            return Err(tuple(problems))

        assert issuance is not None
        payload: dict[str, Any] = {
            "companyVatCode": self._config.company_vat_code,
            "seriesName": issuance.provider_series,
            "number": issuance.provider_number,
        }
        # SmartBill refuses a storno dated before the original. Today is always valid
        # because the original is, by definition, already issued - but it has to be
        # *today in Romania*. Between Romanian and UTC midnight `.date()` yields
        # yesterday, which can predate the original and be refused outright, and near
        # month-end assigns the correction to a VAT period that has closed.
        payload["issueDate"] = ro_local_date(timezone.now()).isoformat()
        return Ok(PreparedDocument(payload=payload, digest=payload_digest(payload)))

    def submit_storno(self, prepared: PreparedDocument, *, attempt_id: UUID) -> IssueOutcome:
        """Post the reversal and classify what comes back."""
        response = self._client.reverse_invoice(prepared.payload)

        if response.verdict is Verdict.AMBIGUOUS:
            logger.error(f"🔥 [SmartBill] Ambiguous storno (attempt {attempt_id}): {response.error_text}")
            return Ambiguous(reason=response.error_text)
        if response.verdict is Verdict.REJECTED:
            return Rejected(errors=(response.error_text, *response.error_codes))

        return Issued(
            number=str(response.payload.get("number") or ""),
            series=str(response.payload.get("series") or ""),
            provider_document_id=str(response.payload.get("documentId") or ""),
            response_digest=payload_digest(response.payload),
        )

    def prepare(self, invoice: Invoice) -> Result[PreparedDocument, tuple[str, ...]]:
        """Build the exact request. Side-effect free, so it is safe before claiming."""
        mapped = build_invoice_payload(invoice, self._config)
        if isinstance(mapped, Err):
            return Err(tuple(mapped.error))
        payload = mapped.unwrap().payload
        return Ok(PreparedDocument(payload=payload, digest=payload_digest(payload)))

    def submit(self, prepared: PreparedDocument, *, attempt_id: UUID) -> IssueOutcome:
        """Post the already-frozen request and classify what comes back."""
        response = self._client.create_invoice(prepared.payload)

        if response.verdict is Verdict.AMBIGUOUS:
            logger.error(f"🔥 [SmartBill] Ambiguous issuance (attempt {attempt_id}): {response.error_text}")
            return Ambiguous(reason=response.error_text)

        if response.verdict is Verdict.REJECTED:
            return Rejected(errors=(response.error_text, *response.error_codes))

        number = str(response.payload.get("number") or "")
        series = str(response.payload.get("series") or "")
        return Issued(
            number=number,
            series=series,
            provider_document_id=str(response.payload.get("documentId") or ""),
            response_digest=payload_digest(response.payload),
        )


def _credentials_from_settings() -> SmartBillCredentials:
    """Operator-managed credentials, with a deployment fallback.

    Read through SettingsService so they are editable at runtime and so secrets stay
    write-only in the UI: the settings surface never renders a stored secret back,
    it only reports whether one is configured.
    """
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SmartBillCredentials(
        email=str(SettingsService.get_setting("integrations.smartbill_email", "") or ""),
        token=str(SettingsService.get_setting("integrations.smartbill_token", "") or ""),
        cif=str(SettingsService.get_setting("integrations.smartbill_cif", "") or ""),
        v3_token=str(SettingsService.get_setting("integrations.smartbill_v3_token", "") or ""),
    )


def _config_from_settings() -> SmartBillAccountConfig:
    """Account-coupled document defaults.

    `tax_names` is deliberately operator-configured rather than derived: selecting a
    VAT rate by percentage alone is unsafe, because two configured rates can share a
    percentage with different fiscal meaning.
    """
    from apps.settings.services import SettingsService  # noqa: PLC0415

    tax_names = SettingsService.get_setting("integrations.smartbill_tax_names", {}) or {}
    cif = str(SettingsService.get_setting("integrations.smartbill_cif", "") or "")
    return SmartBillAccountConfig(
        invoice_series=str(SettingsService.get_setting("integrations.smartbill_invoice_series", "") or ""),
        tax_names=dict(tax_names) if isinstance(tax_names, dict) else {},
        measuring_unit=str(SettingsService.get_setting("integrations.smartbill_measuring_unit", "buc") or "buc"),
        language=str(SettingsService.get_setting("integrations.smartbill_language", "RO") or "RO"),
        company_vat_code=cif,
    )


register_invoice_issuer(SmartBillIssuer.provider, SmartBillIssuer)
