"""The SmartBill implementation of the issuer gateway.

Maps, posts, classifies. It deliberately does no orchestration: claims, retries and
reconciliation live in the issuance service, because those decisions depend on
durable state this object does not own.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING

from django.conf import settings

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
    """Deployment-level credentials.

    Phase 9 moves these to the settings catalog with write-only secret handling;
    reading undeclared keys through SettingsService now would break the ADR-0042
    consumer contract.
    """
    return SmartBillCredentials(
        email=getattr(settings, "SMARTBILL_EMAIL", ""),
        token=getattr(settings, "SMARTBILL_TOKEN", ""),
        cif=getattr(settings, "SMARTBILL_CIF", ""),
        v3_token=getattr(settings, "SMARTBILL_V3_TOKEN", ""),
    )


def _config_from_settings() -> SmartBillAccountConfig:
    return SmartBillAccountConfig(
        invoice_series=getattr(settings, "SMARTBILL_INVOICE_SERIES", ""),
        tax_names=getattr(settings, "SMARTBILL_TAX_NAMES", {}),
        measuring_unit=getattr(settings, "SMARTBILL_MEASURING_UNIT", "buc"),
        language=getattr(settings, "SMARTBILL_LANGUAGE", "RO"),
        company_vat_code=getattr(settings, "SMARTBILL_CIF", ""),
    )


register_invoice_issuer(SmartBillIssuer.provider, SmartBillIssuer)
