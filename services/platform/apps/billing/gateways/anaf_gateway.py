"""
ANAF company lookup for Romanian CUIs (PlatitorTvaRest v9).

Asks ANAF's public register for a company's registered name, address, trade registry number, VAT
registration and status. Uses safe_request() for SSRF protection and the Django cache (24 h for a
company found, 1 h for a CUI not found). ANAF allows one request per second, so a shared claim
spaces the calls; a call that finds the claim taken is answered as rate limited, for the caller to
retry later. With ANAF_TRANSPORT_ENABLED off (development and tests) nothing connects.

ANAF answers a request in which no CUI was found with HTTP 404 and its ordinary JSON body: that is
an answer, not an outage (tests/billing/fixtures/PROVENANCE.md).
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import date
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.common.cui_validator import CUIValidator
from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError, safe_request

logger = logging.getLogger(__name__)

ANAF_API_URL = "https://webservicesp.anaf.ro/api/PlatitorTvaRest/v9/tva"
ANAF_CACHE_PREFIX = "anaf:"
ANAF_CACHE_TTL_FOUND = 24 * 60 * 60
ANAF_CACHE_TTL_NOT_FOUND = 60 * 60
MAX_CUIS_PER_REQUEST = 100
# claim() keeps whole seconds, so a two-second lease leaves at least one second between calls.
SPACING_KEY = "anaf:spacing"
SPACING_SECONDS = 2
_NOT_FOUND = {"not_found": True}
_HTTP_OK = 200
_HTTP_NOT_FOUND = 404

ANAF_POLICY = OutboundPolicy(name="anaf", allowed_domains=frozenset({"webservicesp.anaf.ro"}))


@dataclass(frozen=True)
class AnafCompany:
    """A company as ANAF's register states it."""

    cui: str
    name: str
    address: str = ""
    registration_number: str = ""  # nrRegCom
    vat_registered: bool = False  # scpTVA
    inactive: bool = False  # statusInactivi
    deregistered_on: str = ""  # dataRadiere
    street: str = ""
    city: str = ""
    county: str = ""
    postal_code: str = ""

    @property
    def active(self) -> bool:
        return not self.inactive and not self.deregistered_on


@dataclass(frozen=True)
class AnafLookup:
    """ANAF's answer for some CUIs. api_available is False when ANAF gave none (down, busy or off)."""

    api_available: bool
    companies: dict[str, AnafCompany] = field(default_factory=dict)
    not_found: frozenset[str] = frozenset()
    rate_limited: bool = False


def transport_enabled() -> bool:
    return bool(getattr(settings, "ANAF_TRANSPORT_ENABLED", False))


def _company_from(entry: dict[str, Any]) -> AnafCompany:
    general = entry.get("date_generale") or {}
    vat = entry.get("inregistrare_scop_Tva") or {}
    status = entry.get("stare_inactiv") or {}
    seat = entry.get("adresa_sediu_social") or {}
    street = " ".join(
        part for part in (str(seat.get("sdenumire_Strada") or ""), str(seat.get("snumar_Strada") or "")) if part
    )
    details = str(seat.get("sdetalii_Adresa") or "")
    return AnafCompany(
        cui=str(general.get("cui", "")),
        name=str(general.get("denumire") or ""),
        address=str(general.get("adresa") or ""),
        registration_number=str(general.get("nrRegCom") or ""),
        vat_registered=bool(vat.get("scpTVA")),
        inactive=bool(status.get("statusInactivi")),
        deregistered_on=str(status.get("dataRadiere") or ""),
        street=", ".join(part for part in (street, details) if part),
        city=str(seat.get("sdenumire_Localitate") or ""),
        county=str(seat.get("sdenumire_Judet") or ""),
        postal_code=str(seat.get("scod_Postal") or ""),
    )


def parse_answer(data: dict[str, Any]) -> tuple[dict[str, AnafCompany], frozenset[str]]:
    """The companies found, by CUI, and the CUIs not found, from ANAF's JSON answer."""
    companies = {company.cui: company for company in map(_company_from, data.get("found") or [])}
    return companies, frozenset(str(cui) for cui in data.get("notFound") or [])


def _checked_digits(cuis: Sequence[str]) -> list[str]:
    if len(cuis) > MAX_CUIS_PER_REQUEST:
        raise ValueError(f"ANAF accepts at most {MAX_CUIS_PER_REQUEST} CUIs per request")
    digits = []
    for cui in cuis:
        checked = CUIValidator.validate_strict(cui)
        if not checked.is_valid:
            raise ValueError("Invalid CUI")
        digits.append(checked.digits)
    return list(dict.fromkeys(digits))


def _cached(cuis: list[str]) -> tuple[dict[str, AnafCompany], set[str], list[str]]:
    """The companies and not-found CUIs the cache holds, and the CUIs it does not."""
    companies: dict[str, AnafCompany] = {}
    not_found: set[str] = set()
    missing = []
    for cui in cuis:
        cached = cache.get(f"{ANAF_CACHE_PREFIX}{cui}")
        if cached == _NOT_FOUND:
            not_found.add(cui)
        elif isinstance(cached, dict):
            companies[cui] = AnafCompany(**cached)
        else:
            missing.append(cui)
    return companies, not_found, missing


def _ask_anaf(cuis: list[str], on_date: date) -> tuple[dict[str, AnafCompany], frozenset[str]] | None:
    """ANAF's answer for cuis, or None when it gave none."""
    try:
        response = safe_request(
            "POST",
            ANAF_API_URL,
            policy=ANAF_POLICY,
            json=[{"cui": int(cui), "data": on_date.isoformat()} for cui in cuis],
        )
        if response.status_code not in (_HTTP_OK, _HTTP_NOT_FOUND):
            response.raise_for_status()
        return parse_answer(response.json())
    except OutboundSecurityError:
        logger.error("🔥 [ANAF] SSRF policy violation — request blocked")
        raise  # Never mask security violations
    except Exception as exc:
        logger.warning("⚠️ [ANAF] API unavailable: %s", exc)
        return None


class AnafGateway:
    """ANAF PlatitorTvaRest client with caching, call spacing and graceful degradation."""

    @staticmethod
    def lookup(cuis: Sequence[str], *, on_date: date | None = None) -> AnafLookup:
        """Look up Romanian CUIs (digits, an RO prefix accepted), at most 100 at a time.

        Raises ValueError for more than 100 CUIs or one that fails its check digit.
        """
        companies, not_found, missing = _cached(_checked_digits(cuis))
        if not missing:
            return AnafLookup(api_available=True, companies=companies, not_found=frozenset(not_found))
        if not transport_enabled():
            return AnafLookup(api_available=False)

        from apps.common import counters  # noqa: PLC0415  # Deferred: the model registry must be ready

        if not counters.claim(SPACING_KEY, SPACING_SECONDS, secrets.token_hex(8)):
            return AnafLookup(api_available=False, rate_limited=True)
        answer = _ask_anaf(missing, on_date or timezone.localdate())
        if answer is None:
            return AnafLookup(api_available=False)

        answered, unknown = answer
        for cui in missing:
            if cui in answered:
                companies[cui] = answered[cui]
                cache.set(f"{ANAF_CACHE_PREFIX}{cui}", asdict(answered[cui]), ANAF_CACHE_TTL_FOUND)
            elif cui in unknown:
                not_found.add(cui)
                cache.set(f"{ANAF_CACHE_PREFIX}{cui}", _NOT_FOUND, ANAF_CACHE_TTL_NOT_FOUND)
            else:
                # Neither found nor not found: ANAF did not answer for it.
                return AnafLookup(api_available=False)
        return AnafLookup(api_available=True, companies=companies, not_found=frozenset(not_found))
