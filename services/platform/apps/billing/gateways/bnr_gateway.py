"""BNR daily exchange-rate gateway with SSRF protection and batch validation (#103).

Rates are RON per one foreign-currency unit.

Caller contract:
* Fetch BEFORE opening the database write transaction, so a propagated security
  exception does not roll back the gateway's security audit.
* On api_available=False, retain existing rates and report ingestion failure.
* Derive as_of = publication_date + timedelta(days=1), one CALENDAR day, under
  Cod Fiscal art. 290(2) and Norme pct. 35 (the last rate communicated strictly
  before the tax point). Never derive as_of from tax_point - 1 or a working-day
  calendar.
* Wrap all record_fx_rate() calls for a publication in one transaction.atomic()
  block, so any storage validation failure or conflict rolls back the batch.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal, DecimalException, Inexact, localcontext
from zoneinfo import ZoneInfo

from django.utils import timezone
from lxml import etree
from requests import RequestException

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError, safe_request

logger = logging.getLogger(__name__)

BNR_API_URL = "https://curs.bnr.ro/nbrfxrates.xml"
BNR_NAMESPACE = "https://www.bnr.ro/xsd"
BNR_POLICY = OutboundPolicy(
    name="bnr",
    allowed_domains=frozenset({"curs.bnr.ro"}),
    allow_redirects=False,
    max_redirects=0,
)
RO_TIMEZONE = ZoneInfo("Europe/Bucharest")
MAX_FEED_BYTES = 64 * 1024
HTTP_OK = 200


@dataclass(frozen=True)
class BNRResponse:
    """A fully validated publication, or an unavailable result with no rates."""

    publication_date: date | None = None
    rates: dict[str, Decimal] = field(default_factory=dict)
    api_available: bool = False
    error_message: str = ""


def _tag(name: str) -> str:
    return f"{{{BNR_NAMESPACE}}}{name}"


def _require_children(element: etree._Element, names: tuple[str, ...]) -> None:
    """Validate direct children, their namespace, order and cardinality."""
    if [child.tag for child in element] != [_tag(name) for name in names]:
        raise ValueError(f"Unexpected BNR structure in {element.tag}")


def _text(element: etree._Element) -> str:
    if len(element):
        raise ValueError(f"Expected text-only BNR element: {element.tag}")
    value = (element.text or "").strip()
    if not value:
        raise ValueError(f"Empty BNR element: {element.tag}")
    return value


def _publication_date(value: str) -> date:
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
        raise ValueError("BNR publication date must be YYYY-MM-DD")
    return date.fromisoformat(value)


def _positive_decimal(value: str) -> Decimal:
    number = Decimal(value)
    if not number.is_finite() or number <= 0:
        raise ValueError("BNR amounts and multipliers must be finite and positive")
    # XML decimal notation: reject exponent notation and Decimal's underscores.
    if re.fullmatch(r"\+?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)", value) is None:
        raise ValueError("Invalid BNR decimal notation")
    return number


def _parse_rates(cube: etree._Element) -> dict[str, Decimal]:
    if not len(cube):
        raise ValueError("BNR publication contains no rates")

    rates: dict[str, Decimal] = {}
    for element in cube:
        if element.tag != _tag("Rate"):
            raise ValueError("Unexpected element in BNR publication")
        if not {"currency"} <= set(element.attrib) <= {"currency", "multiplier"}:
            raise ValueError("Invalid BNR Rate attributes")

        currency = str(element.attrib["currency"])  # lxml stubs over-declare str|bytes
        if re.fullmatch(r"[A-Z]{3}", currency) is None or currency == "RON":
            raise ValueError(f"Invalid BNR foreign currency: {currency}")
        if currency in rates:
            raise ValueError(f"Duplicate BNR currency: {currency}")

        amount = _positive_decimal(_text(element))
        multiplier_text = str(element.get("multiplier", "1")).strip()
        multiplier = _positive_decimal(multiplier_text)
        if re.fullmatch(r"\+?[0-9]+", multiplier_text) is None:
            raise ValueError(f"BNR multiplier must be a positive integer: {currency}")

        # Do not silently round unexpected feed values during normalization.
        with localcontext() as context:
            context.prec = 28
            context.traps[Inexact] = True
            normalized = amount / multiplier

        if not normalized.is_finite() or normalized <= 0:
            raise ValueError(f"Invalid normalized BNR rate: {currency}")
        rates[currency] = normalized

    return rates


def _parse_feed(content: bytes, requested: tuple[str, ...], today: date) -> BNRResponse:
    if not content or len(content) > MAX_FEED_BYTES:
        raise ValueError("BNR feed is empty or exceeds the parsing size limit")

    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        huge_tree=False,
        recover=False,
        remove_comments=True,
        remove_pis=True,
    )
    root = etree.fromstring(content, parser=parser)
    if getattr(root.getroottree().docinfo, "doctype", None):
        raise ValueError("BNR feed must not contain a DTD")
    if root.tag != _tag("DataSet"):
        raise ValueError("Unexpected BNR root element or namespace")

    # Validate the daily feed's structural schema locally. Never follow the document's
    # schemaLocation or fetch a schema/DTD over the network.
    _require_children(root, ("Header", "Body"))
    header, body = root
    _require_children(header, ("Publisher", "PublishingDate", "MessageType"))
    _text(header[0])
    header_date = _publication_date(_text(header[1]))
    if _text(header[2]) != "DR":
        raise ValueError("Expected a BNR daily-rate message")

    body_names: tuple[str, ...] = ("Subject", "OrigCurrency", "Cube")
    if any(child.tag == _tag("Description") for child in body):
        body_names = ("Subject", "Description", "OrigCurrency", "Cube")
    _require_children(body, body_names)
    for child in list(body)[:-1]:
        _text(child)
    if _text(body[-2]) != "RON":
        raise ValueError("BNR quote currency must be RON")

    cube = body[-1]
    if set(cube.attrib) != {"date"}:
        raise ValueError("BNR Cube must have exactly one publication-date attribute")
    publication_date = _publication_date(str(cube.attrib["date"]))
    if publication_date != header_date:
        # A well-formed BNR feed carries the same date in the Header and the Cube; a mismatch
        # is a corrupted/inconsistent publication — reject rather than stamp a legally
        # significant tax-point date from an untrusted Cube value.
        raise ValueError("BNR Header PublishingDate does not match the Cube date")
    if publication_date > today:
        raise ValueError("BNR publication date is in the future in Europe/Bucharest")

    # Parse every feed row before selecting requested currencies. A malformed
    # unrequested row also invalidates the publication.
    rates = _parse_rates(cube)
    missing = sorted(set(requested) - rates.keys())
    if missing:
        raise ValueError(f"BNR feed is missing requested currencies: {', '.join(missing)}")

    return BNRResponse(
        publication_date=publication_date,
        rates={currency: rates[currency] for currency in requested},
        api_available=True,
    )


def _audit_security_failure(exc: OutboundSecurityError) -> None:
    """Attempt a durable audit without replacing the original security error."""
    try:
        from apps.audit.services import AuditService  # noqa: PLC0415

        AuditService.log_simple_event(
            "security_bnr_outbound_blocked",
            description="BNR exchange-rate request blocked by outbound security policy",
            metadata={
                "url": BNR_API_URL,
                "policy": BNR_POLICY.name,
                "error": str(exc),
                "severity": "high",
            },
            actor_type="system",
        )
    except Exception:
        # AuditService failures must never mask the OutboundSecurityError.
        logger.exception("🔥 [BNR] Failed to audit outbound security violation")


class BNRGateway:
    """BNR daily-feed client with graceful degradation and no database FX writes."""

    @staticmethod
    def fetch_rates(
        currencies: Iterable[str],
        *,
        now: datetime | None = None,
    ) -> BNRResponse:
        """Return all requested rates, or an unavailable result with no rates.

        ``now``, when supplied, must be timezone-aware. It provides deterministic
        date-boundary tests without mocking the parser or Django's clock.
        """
        try:
            if isinstance(currencies, str):
                raise ValueError("BNR currencies must be a collection of ISO codes")
            requested = tuple(sorted({currency.strip().upper() for currency in currencies}))
            if not requested or any(
                re.fullmatch(r"[A-Z]{3}", currency) is None or currency == "RON" for currency in requested
            ):
                raise ValueError("BNR requires at least one foreign ISO currency code")

            observed_at = timezone.now() if now is None else now
            today = timezone.localdate(observed_at, timezone=RO_TIMEZONE)

            response = safe_request("GET", BNR_API_URL, policy=BNR_POLICY)
            response.raise_for_status()
            # raise_for_status() accepts 3xx. Explicitly reject redirects and other
            # non-200 responses, even if their body resembles valid XML.
            if response.status_code != HTTP_OK:
                raise ValueError(f"Unexpected BNR HTTP status: {response.status_code}")

            return _parse_feed(response.content, requested, today)

        except OutboundSecurityError as exc:
            logger.error("🔥 [BNR] Outbound security policy blocked the exchange-rate request")
            _audit_security_failure(exc)
            raise
        except (RequestException, etree.XMLSyntaxError, DecimalException, ValueError) as exc:
            logger.warning("⚠️ [BNR] Exchange-rate feed unavailable or invalid: %s", exc)
            return BNRResponse(error_message=f"BNR exchange-rate feed unavailable or invalid: {exc}")
