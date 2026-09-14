"""Services-only D390 draft serialization and local ANAF validation.

No filing, VIES request, rate lookup, or accountant certification occurs here.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import cast

from lxml import etree

from apps.billing.ec_sales_service import SERVICE_COUNTRIES, ECSalesReport, ReportingPeriod
from apps.billing.efactura.xml_builder import CompanyInfo, get_supplier_info
from apps.billing.tax_evidence import vat_country
from apps.common.cui_validator import CUIValidator
from apps.common.eu_vat_validator import validate_vat_format

NAMESPACE = "mfp:anaf:dgti:d390:declaratie:v3"
DRAFT_LABEL = "Services-only draft for accountant review."
SCHEMA_SHA256 = "7f95c80866051edec98fb71bed7b2de6957583f35a69fdd8a4ce4f6973487090"
ANNEX_SHA256 = "83ff54cee3c1a636e29a9a8556a92d06ef515f9f2424c36eb20c8d17d3f5ffec"
SCHEMA_DIR = Path(__file__).with_name("d390_schema")
_CHARACTERS = re.compile(r"[A-Za-z0-9 +.@-]+\Z")
_MAX_BASE = 999_999_999_999_999


class D390ExportError(ValueError):
    """An incomplete or unsupported declaration cannot be downloaded as XML."""


@dataclass(frozen=True)
class Declarant:
    surname: str
    given_name: str
    role: str


def _text_field(value: str, field: str, limit: int) -> None:
    if not value.strip() or len(value) > limit or not _CHARACTERS.fullmatch(value):
        raise D390ExportError(
            f"{field}: required, at most {limit} characters; the pinned ANAF annex permits letters A-Z/a-z, digits, spaces and + - . @."
        )


def validate_supplier(supplier: CompanyInfo) -> str:
    """Require complete Romanian supplier identity using the existing settings resolver."""
    if vat_country(supplier.country_code) != "RO":
        raise D390ExportError("Supplier country must be Romania.")
    cui = CUIValidator.validate_strict(supplier.tax_id)
    if not cui.is_valid:
        raise D390ExportError("Supplier CUI fails local checksum validation.")
    _text_field(supplier.name, "Supplier name", 200)
    _text_field(supplier.street, "Supplier street", 800)
    _text_field(supplier.city, "Supplier city", 150)
    _text_field(supplier.postal_code, "Supplier postal code", 20)
    return cui.digits


@lru_cache(maxsize=1)
def compatibility_schema() -> etree.XMLSchema:
    """Keep the official bytes; apply only cos.minOccurs=0, as the annex specifies."""
    original = (SCHEMA_DIR / "d390_12022021.xsd").read_bytes()
    annex = (SCHEMA_DIR / "structura_D390_2020_300424.pdf").read_bytes()
    if hashlib.sha256(original).hexdigest() != SCHEMA_SHA256 or hashlib.sha256(annex).hexdigest() != ANNEX_SHA256:
        raise D390ExportError("Pinned D390 schema or validation annex checksum mismatch.")
    root = etree.fromstring(original, parser=etree.XMLParser(resolve_entities=False, no_network=True))
    elements = root.findall(".//{http://www.w3.org/2001/XMLSchema}element[@name='cos']")
    if len(elements) != 1 or elements[0].get("minOccurs") is not None:
        raise D390ExportError("Unexpected D390 schema compatibility patch target.")
    elements[0].set("minOccurs", "0")
    return etree.XMLSchema(root)


def _validate_operations(operations: list[etree._Element]) -> int:
    """Check the service-specific partner uniqueness and amounts in the annex."""
    seen: set[tuple[str, str]] = set()
    total = 0
    for row in operations:
        country, body = row.get("tara", ""), row.get("codO", "")
        if row.attrib["tip"] != "P" or country not in SERVICE_COUNTRIES:
            raise D390ExportError("Only outgoing EU services, operation P, are supported.")
        if not body or not validate_vat_format(country, body).is_valid:
            raise D390ExportError("Invalid partner VAT identifier.")
        _text_field(row.get("denO", ""), "Partner name", 200)
        if (country, body) in seen:
            raise D390ExportError("Duplicate partner VAT identity.")
        seen.add((country, body))
        amount = int(row.attrib["baza"])
        if not 0 < amount <= _MAX_BASE:
            raise D390ExportError("Initial service supplies must have a positive base within 15 digits.")
        total += amount
    return total


def validate_d390_xml(content: bytes) -> None:
    """Check the pinned compatibility XSD plus applicable service/initial annex rules."""
    try:
        root = etree.fromstring(content, parser=etree.XMLParser(resolve_entities=False, no_network=True))
        compatibility_schema().assertValid(root)
        ReportingPeriod(int(root.attrib["an"]), int(root.attrib["luna"]))
        if root.attrib["d_rec"] != "0":
            raise D390ExportError("Only initial declarations are supported.")
        for key, limit in (
            ("nume_declar", 75),
            ("prenume_declar", 75),
            ("functie_declar", 50),
            ("den", 200),
            ("adresa", 1000),
        ):
            _text_field(root.get(key, ""), key, limit)
        if not CUIValidator.validate_strict(root.get("cui", "")).is_valid:
            raise D390ExportError("Invalid supplier CUI.")
        if root.find(f"{{{NAMESPACE}}}cos") is not None:
            raise D390ExportError("Stock transfers are outside the supported services scope.")
        operations = root.findall(f"{{{NAMESPACE}}}operatie")
        total = _validate_operations(operations)
        summary = root.find(f"{{{NAMESPACE}}}rezumat")
        assert summary is not None  # Required by the schema.
        expected = {
            "nrOPI": len(operations),
            "bazaP": total,
            "total_baza": total,
            "bazaL": 0,
            "bazaT": 0,
            "bazaA": 0,
            "bazaS": 0,
            "bazaR": 0,
        }
        if any(int(summary.attrib[key]) != value for key, value in expected.items()):
            raise D390ExportError("D390 summary does not reconcile to operation rows.")
        control = total + len(operations)
        if not operations or control > _MAX_BASE or int(root.attrib["totalPlata_A"]) != control:
            raise D390ExportError("D390 control total is invalid or the period is empty.")
    except (etree.XMLSyntaxError, etree.DocumentInvalid, KeyError, ValueError) as exc:
        raise D390ExportError(str(exc)) from exc


def render_d390_xml(report: ECSalesReport, declarant: Declarant) -> bytes:
    """Render deterministic draft bytes only after complete candidate reconciliation."""
    report.assert_reconciled()
    if not report.can_export:
        raise D390ExportError("XML export requires a non-empty period with no blocking exceptions.")
    supplier = get_supplier_info()
    cui = validate_supplier(supplier)
    root = etree.Element(
        f"{{{NAMESPACE}}}declaratie390",
        nsmap=cast(dict[str, str], {None: NAMESPACE}),
        attrib={
            "luna": str(report.period.month),
            "an": str(report.period.year),
            "d_rec": "0",
            "nume_declar": declarant.surname,
            "prenume_declar": declarant.given_name,
            "functie_declar": declarant.role,
            "cui": cui,
            "den": supplier.name,
            "adresa": f"{supplier.street} {supplier.city} {supplier.postal_code}",
            "totalPlata_A": str(report.rounded_ron + len(report.partners)),
        },
    )
    etree.SubElement(
        root,
        f"{{{NAMESPACE}}}rezumat",
        attrib={
            # One logical XML annex; no physical PDF pagination is generated.
            "nr_pag": "1",
            "nrOPI": str(len(report.partners)),
            "bazaL": "0",
            "bazaT": "0",
            "bazaA": "0",
            "bazaP": str(report.rounded_ron),
            "bazaS": "0",
            "bazaR": "0",
            "total_baza": str(report.rounded_ron),
        },
    )
    for partner in report.partners:
        etree.SubElement(
            root,
            f"{{{NAMESPACE}}}operatie",
            attrib={
                "tip": partner.operation,
                "tara": partner.country,
                "codO": partner.vat_body,
                "denO": partner.partner_name,
                "baza": str(partner.rounded_ron),
            },
        )
    content = etree.tostring(root, encoding="UTF-8", xml_declaration=True, pretty_print=True)
    validate_d390_xml(content)
    return content


def _csv_text(value: str) -> str:
    """Do not interpret invoice descriptions or partner names as spreadsheet formulas."""
    return f"'{value}" if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else value


def render_reconciliation_csv(report: ECSalesReport) -> bytes:
    """Make contributions, partner rounding and blocking exceptions downloadable together."""
    report.assert_reconciled()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([DRAFT_LABEL, report.period.label, "Source SHA-256", report.source_fingerprint])
    writer.writerow(
        [
            "Record",
            "Invoice",
            "Invoice ID",
            "Line ID",
            "Tax point",
            "Country",
            "VAT body",
            "Partner",
            "Operation",
            "Currency",
            "Gross cents",
            "Discount cents",
            "RON rate",
            "RON base",
            "Whole lei",
            "Rounding difference",
            "Exception codes",
            "Details",
            "Captured VIES status",
            "VIES consultation reference",
        ]
    )
    for line in report.contributions:
        writer.writerow(
            [
                "included",
                _csv_text(line.invoice_number),
                line.invoice_id,
                line.line_id,
                line.tax_point_date,
                line.country,
                f"'{line.vat_body}",
                _csv_text(line.partner_name),
                line.operation,
                line.currency,
                line.gross_cents,
                line.discount_cents,
                line.exchange_rate,
                line.base_ron,
                "",
                "",
                "",
                _csv_text(line.description),
                line.vies_status,
                _csv_text(line.consultation_reference),
            ]
        )
    for partner in report.partners:
        writer.writerow(
            [
                "partner_total",
                "",
                "",
                "",
                "",
                partner.country,
                f"'{partner.vat_body}",
                _csv_text(partner.partner_name),
                partner.operation,
                "RON",
                "",
                "",
                "",
                partner.base_ron,
                partner.rounded_ron,
                partner.rounding_difference,
                "",
                "",
                "",
                "",
            ]
        )
    for exc in report.exceptions:
        writer.writerow(
            [
                "exception",
                _csv_text(exc.invoice_number),
                exc.invoice_id,
                exc.line_id,
                exc.tax_point_date,
                "",
                "",
                "",
                "",
                exc.currency,
                exc.gross_cents,
                "",
                "",
                "",
                "",
                "",
                "|".join(exc.codes),
                _csv_text(exc.detail),
                "",
                "",
            ]
        )
    return output.getvalue().encode("utf-8-sig")
