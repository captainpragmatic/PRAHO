"""Recorded VAT decisions shared by billing documents and statutory review reports.

This records the existing tax engine's decision; entitlement policy remains in
TaxService. Reading evidence never consults a customer profile or a remote API.
An empty snapshot means unknown, including for historical and manual documents.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from django.utils.dateparse import parse_datetime

from apps.billing.fiscal_identity import normalize_country_code
from apps.common.eu_vat_validator import EU_COUNTRIES, parse_vat_number
from apps.common.tax_service import VATCalculationResult, VATScenario

if TYPE_CHECKING:
    from apps.billing.invoice_models import Invoice
    from apps.billing.proforma_models import ProformaInvoice

REVERSE_CHARGE_LEGAL_BASIS = "Art. 196 Council Directive 2006/112/EC"
EVIDENCE_VERSION = 2
SUPPORTED_EVIDENCE_VERSIONS = frozenset({1, 2})
# Snapshots from this version on were written while the consultation-reference policy was enforceable.
CONSULTATION_REFERENCE_EVIDENCE_VERSION = 2
# A built-in credit note's evidence (ADR-0053): its original's decision, written under the
# original's version (`original_version`), with the note's own signed amounts. Only ever valid on
# a credit note, whose amounts are <= 0.
CREDIT_NOTE_EVIDENCE_VERSION = 3
# The decision fields a note restates from its original, unchanged.
_RESTATED_DECISION_FIELDS = (
    "scenario",
    "category",
    "country_code",
    "vat_number",
    "is_business",
    "vat_rate_percent",
)


class TaxEvidenceError(ValueError):
    """Recorded evidence is malformed or internally inconsistent."""


def vat_country(country: str) -> str:
    """Use the VAT-issuing code EL for Greece, preserving other ISO codes."""
    if country.strip().upper() in EU_COUNTRIES | {"XI"}:
        return country.strip().upper()
    normalized = normalize_country_code(country)
    return "EL" if normalized == "GR" else normalized


def vat_identity(raw: str, country: str) -> tuple[str, str]:
    """Parse a VAT identity without dropping leading zeros or ignoring a prefix."""
    prefix, body = parse_vat_number(raw, default_country=vat_country(country))
    return vat_country(prefix), body


def derive_tax_category(result: VATCalculationResult) -> str:
    """An explicit reverse-charge decision takes precedence over generic zero VAT."""
    if result.scenario == VATScenario.EU_B2B_REVERSE_CHARGE:
        return "AE"
    if result.scenario == VATScenario.NON_EU_ZERO_VAT:
        return "O"
    return "Z" if result.vat_rate == 0 else "S"


def capture_vat_evidence(result: VATCalculationResult) -> dict[str, Any]:
    """Copy the decision and any contemporaneous cached validation, without I/O to VIES."""
    from apps.billing.config import get_vies_evidence_max_age_days  # noqa: PLC0415
    from apps.billing.tax_models import VATValidation  # noqa: PLC0415  # Avoid a billing model import cycle.

    calculated_at = result.audit_data["calculated_at"]
    evidence: dict[str, Any] = {
        "version": EVIDENCE_VERSION,
        "scenario": result.scenario.value,
        "category": derive_tax_category(result),
        "country_code": result.country_code,
        "vat_number": result.vat_number or "",
        "is_business": result.is_business,
        "vat_rate_percent": str(result.vat_rate),
        "subtotal_cents": result.subtotal_cents,
        "tax_cents": result.vat_cents,
        "total_cents": result.total_cents,
        "calculated_at": calculated_at,
        "evidence_max_age_days": get_vies_evidence_max_age_days(),
        "vies": None,
    }
    if result.vat_number:
        country, body = vat_identity(result.vat_number, result.country_code)
        validation = VATValidation.objects.filter(
            country_code=country, vat_number=body, validation_date__lte=calculated_at
        ).first()
        if validation:
            evidence["vies"] = {
                "country_code": validation.country_code,
                "vat_number": validation.vat_number,
                "is_valid": validation.is_valid,
                "is_active": validation.is_active,
                "source": validation.validation_source,
                "validated_at": validation.validation_date.isoformat(),
                "expires_at": validation.expires_at.isoformat() if validation.expires_at else None,
                "consultation_reference": validation.consultation_reference,
                "company_name": validation.company_name,
                "company_address": validation.company_address,
            }
    return evidence


@dataclass(frozen=True)
class VATDecision:
    """Validated, versioned decision; absence of VIES proof does not invent entitlement."""

    scenario: VATScenario
    category: str
    country: str
    vat_number: str
    is_business: bool
    rate: Decimal
    subtotal_cents: int
    tax_cents: int
    total_cents: int


def _validate_timestamp(data: dict[str, Any], field: str) -> None:
    if not isinstance(data[field], str):
        raise ValueError(f"Invalid {field}")
    timestamp = parse_datetime(data[field])
    if timestamp is None or timestamp.utcoffset() is None:
        raise ValueError(f"Missing {field} with timezone")


def _validate_snapshot_fields(data: dict[str, Any], *, credit: bool = False) -> None:
    """Validate the primitive fields before decoding the decision.

    A credit (version 3) carries amounts <= 0; every other snapshot carries amounts >= 0.
    """
    for field in ("country_code", "vat_number", "calculated_at", "vat_rate_percent", "category"):
        if not isinstance(data[field], str):
            raise ValueError(f"Invalid {field}")
    _validate_timestamp(data, "calculated_at")
    if type(data["is_business"]) is not bool:
        raise ValueError("Missing business decision")
    for field in ("subtotal_cents", "tax_cents", "total_cents"):
        if type(data[field]) is not int or (data[field] > 0 if credit else data[field] < 0):
            raise ValueError(f"Invalid {field}")


def _validate_credit_note_snapshot(document: Invoice | ProformaInvoice, data: dict[str, Any]) -> None:
    """Version 3 holds only on a credit note, and only for that note's own amounts."""
    from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE  # noqa: PLC0415  # Avoid model import cycle.

    if getattr(document, "document_kind", None) != DOCUMENT_KIND_CREDIT_NOTE:
        raise ValueError("Credit-note evidence on a document that is not a credit note")
    if data["document_kind"] != DOCUMENT_KIND_CREDIT_NOTE:
        raise ValueError("Credit-note evidence that does not say it is one")
    if type(data["original_version"]) is not int or data["original_version"] not in SUPPORTED_EVIDENCE_VERSIONS:
        raise ValueError("Unknown original evidence version")
    if not isinstance(data["reverses_number"], str) or not data["reverses_number"].strip():
        raise ValueError("Missing reversed document number")
    _validate_timestamp(data, "reverses_calculated_at")
    stated = (data["subtotal_cents"], data["tax_cents"], data["total_cents"])
    if stated != (document.subtotal_cents, document.tax_cents, document.total_cents):
        raise ValueError("Credit-note evidence amounts disagree with the credit note")


def evidence_rules_version(data: dict[str, Any]) -> int:
    """The version whose rules judge this snapshot's proof.

    A credit note's proof is its original's, so it is judged as its original was: a version 3
    snapshot answers with the original's version, every other one with its own.
    """
    version = data.get("version", 0)
    if version == CREDIT_NOTE_EVIDENCE_VERSION:
        return int(data.get("original_version", 0))
    return int(version) if type(version) is int else 0


def capture_credit_note_evidence(
    original: Invoice, *, subtotal_cents: int, tax_cents: int, total_cents: int
) -> dict[str, Any]:
    """The version 3 snapshot for a credit note of `original`, written before the note is issued.

    The decision, identity and VIES proof are the original's, unchanged: a correction restates the
    supply it corrects rather than re-deciding it. An original with no recorded decision (a
    historical or manual document) gives a note with none either, which reads as unknown.
    """
    from django.utils import timezone  # noqa: PLC0415

    from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE  # noqa: PLC0415  # Avoid model import cycle.

    if read_vat_evidence(original) is None:
        return {}
    source = original.vat_evidence
    evidence: dict[str, Any] = {
        "version": CREDIT_NOTE_EVIDENCE_VERSION,
        "document_kind": DOCUMENT_KIND_CREDIT_NOTE,
        "original_version": source["version"],
        "reverses_number": original.number or "",
        "reverses_calculated_at": source["calculated_at"],
        **{field: source[field] for field in _RESTATED_DECISION_FIELDS},
        "subtotal_cents": subtotal_cents,
        "tax_cents": tax_cents,
        "total_cents": total_cents,
        "calculated_at": timezone.now().isoformat(),
        "vies": deepcopy(source.get("vies")),
    }
    if "evidence_max_age_days" in source:
        evidence["evidence_max_age_days"] = source["evidence_max_age_days"]
    return evidence


def read_vat_evidence(document: Invoice | ProformaInvoice) -> VATDecision | None:
    """Decode recorded evidence, rejecting unknown versions and partial snapshots."""
    data = getattr(document, "vat_evidence", {})
    if data == {}:
        return None
    try:
        if not isinstance(data, dict) or type(data["version"]) is not int:
            raise ValueError("Unknown evidence version")
        credit = data["version"] == CREDIT_NOTE_EVIDENCE_VERSION
        if credit:
            _validate_credit_note_snapshot(document, data)
        elif data["version"] not in SUPPORTED_EVIDENCE_VERSIONS:
            raise ValueError("Unknown evidence version")
        _validate_snapshot_fields(data, credit=credit)
        rate = Decimal(data["vat_rate_percent"])
        if not rate.is_finite() or rate < 0:
            raise ValueError("Invalid VAT rate")
        scenario = VATScenario(data["scenario"])
        category = "Z" if rate == 0 else "S"
        if scenario == VATScenario.EU_B2B_REVERSE_CHARGE:
            category = "AE"
        elif scenario == VATScenario.NON_EU_ZERO_VAT:
            category = "O"
        if data["category"] != category or (category in {"AE", "O"} and rate != 0):
            raise ValueError("VAT category disagrees with decision")
        if data["subtotal_cents"] + data["tax_cents"] != data["total_cents"]:
            raise ValueError("Decision totals disagree")
        return VATDecision(
            scenario,
            category,
            vat_country(data["country_code"]),
            data["vat_number"],
            data["is_business"],
            rate,
            data["subtotal_cents"],
            data["tax_cents"],
            data["total_cents"],
        )
    except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
        raise TaxEvidenceError(f"Invalid recorded VAT evidence: {exc}") from exc


def recorded_tax_category(document: Invoice | ProformaInvoice) -> str | None:
    """Return an explicit category; None permits legacy rendering compatibility only."""
    decision = read_vat_evidence(document)
    return decision.category if decision else None
