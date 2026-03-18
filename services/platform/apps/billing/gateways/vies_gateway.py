"""
VIES REST API Gateway for PRAHO Platform.

Calls the EU VIES REST API to verify VAT numbers for cross-border B2B
reverse-charge eligibility. Uses safe_request() for SSRF protection and
Django cache for result caching (24h valid, 1h invalid).
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from django.core.cache import cache

from apps.common.outbound_http import STRICT_EXTERNAL, OutboundSecurityError, safe_request

logger = logging.getLogger(__name__)

VIES_API_URL = "https://ec.europa.eu/taxation_customs/vies/rest-api/check-vat-number"
VIES_CACHE_PREFIX = "vies:"
VIES_CACHE_TTL_VALID = 24 * 60 * 60  # 24 hours
VIES_CACHE_TTL_INVALID = 60 * 60  # 1 hour


@dataclass
class VIESResponse:
    """Standardised result from a VIES API call."""

    is_valid: bool
    country_code: str
    vat_number: str
    company_name: str = ""
    company_address: str = ""
    request_date: str = ""
    api_available: bool = True
    error_message: str = ""
    raw_response: dict[str, Any] = field(default_factory=dict)


class VIESGateway:
    """VIES REST API client with caching and graceful degradation."""

    @staticmethod
    def check_vat(country_code: str, vat_number: str) -> VIESResponse:
        """Verify a VAT number against the VIES REST API.

        Args:
            country_code: 2-letter EU country code (e.g., "DE", "FR").
            vat_number: VAT body without country prefix.

        Returns:
            VIESResponse. Check api_available to distinguish
            "VIES says invalid" from "VIES is down".
        """
        country_code = country_code.upper()
        cache_key = f"{VIES_CACHE_PREFIX}{country_code}_{vat_number}"

        cached = cache.get(cache_key)
        if isinstance(cached, dict):
            logger.debug("[VIES] Cache hit: %s%s", country_code, vat_number)
            try:
                return VIESResponse(**cached)
            except TypeError:
                logger.warning("[VIES] Corrupt cache entry for %s%s — evicting", country_code, vat_number)
                cache.delete(cache_key)

        logger.info("[VIES] Querying API: %s%s", country_code, vat_number)
        try:
            response = safe_request(
                "POST",
                VIES_API_URL,
                policy=STRICT_EXTERNAL,
                json={"countryCode": country_code, "vatNumber": vat_number},
            )
            response.raise_for_status()
            data: dict[str, Any] = response.json()

            result = VIESResponse(
                is_valid=bool(data.get("isValid", False)),
                country_code=data.get("countryCode", country_code),
                vat_number=data.get("vatNumber", vat_number),
                company_name=data.get("name", "") or "",
                company_address=data.get("address", "") or "",
                request_date=data.get("requestDate", ""),
                api_available=True,
                raw_response=data,
            )

            ttl = VIES_CACHE_TTL_VALID if result.is_valid else VIES_CACHE_TTL_INVALID
            cache.set(cache_key, asdict(result), ttl)
            return result

        except OutboundSecurityError:
            logger.error("[VIES] SSRF policy violation for %s%s — request blocked", country_code, vat_number)
            raise  # Never mask security violations
        except Exception as exc:
            logger.warning("[VIES] API unavailable for %s%s: %s", country_code, vat_number, exc)
            return VIESResponse(
                is_valid=False,
                country_code=country_code,
                vat_number=vat_number,
                api_available=False,
                error_message="VIES service temporarily unavailable",
            )
