"""The hosting-dns settings that account names read (ADR-0061), and the checks on writing them.

Each value is read through ``SettingsService`` at call time. The checks here are offline: they run
inside the settings write's row lock, whose transaction retries, so they never call the DNS
provider. Whether the token can read and edit the zone is proven where it is used, by every sync,
which publishes nothing when it cannot.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from django.conf import settings

from apps.settings.services import SettingsService

ENABLED = "dns.account_hostnames_enabled"
ZONE = "dns.account_hostname_zone"
ZONE_ID = "dns.account_hostname_zone_id"
API_TOKEN = "dns.account_zone_api_token"  # noqa: S105  # A setting key, not a secret
RECORD_TTL = "dns.account_record_ttl_seconds"
PSL_SHIPPED = "dns.account_zone_psl_shipped"
CERT_WEEKLY_BUDGET = "dns.account_cert_weekly_budget"
ACME_DIRECTORY = "dns.account_acme_directory_url"

LETS_ENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
# A brand address shows which registrable domains the brand and its mail live under.
_BRAND_EMAIL_KEYS = ("company.email_contact", "company.email_support", "company.email_noreply")


def account_hostnames_enabled() -> bool:
    return SettingsService.get_boolean_setting(ENABLED, False)


def account_zone() -> str:
    return _normal_name(str(SettingsService.get_setting(ZONE, "") or ""))


def account_zone_id() -> str:
    return str(SettingsService.get_setting(ZONE_ID, "") or "").strip()


def account_zone_api_token() -> str:
    return str(SettingsService.get_setting(API_TOKEN, "") or "").strip()


def account_record_ttl_seconds() -> int:
    return SettingsService.get_integer_setting(RECORD_TTL, 300)


def account_zone_psl_shipped() -> bool:
    """Whether the zone's Public Suffix List entry is in shipped browsers; until then no customer content."""
    return SettingsService.get_boolean_setting(PSL_SHIPPED, False)


def account_cert_weekly_budget() -> int:
    return SettingsService.get_integer_setting(CERT_WEEKLY_BUDGET, 40)


def acme_directory_url() -> str:
    return str(SettingsService.get_setting(ACME_DIRECTORY, LETS_ENCRYPT_DIRECTORY) or LETS_ENCRYPT_DIRECTORY)


def _normal_name(name: str) -> str:
    return name.strip().strip(".").lower()


def _registrable(name: str) -> str | None:
    """The registrable domain of a name, private suffixes included (github.io users are separate sites)."""
    from publicsuffixlist import PublicSuffixList  # noqa: PLC0415  # Deferred: loads the list on first use

    return PublicSuffixList().privatesuffix(_normal_name(name))


def _brand_names() -> list[str]:
    names = [getattr(settings, "PORTAL_DOMAIN", ""), getattr(settings, "PLATFORM_DOMAIN", "")]
    portal_url = str(SettingsService.get_setting("portal.public_base_url", "") or "")
    names.append(urlsplit(portal_url).hostname or "")
    for key in _BRAND_EMAIL_KEYS:
        address = str(SettingsService.get_setting(key, "") or "")
        names.append(address.rpartition("@")[2])
    return [name for name in (_normal_name(n) for n in names) if name]


def _live_names_exist() -> bool:
    from apps.provisioning.account_hostname_models import AccountHostname  # noqa: PLC0415  # Deferred: app registry

    return AccountHostname.objects.filter(retired_at__isnull=True).exists()


_DNS_NAME_MAX = 253
_DNS_LABEL_MAX = 63


def setting_refusal(key: str, value: Any) -> tuple[str, str] | None:
    """Why a hosting-dns write is refused, as (code, message), or None when it may be stored."""
    if key == ZONE:
        zone = _normal_name(str(value or ""))
        if zone and (len(zone) > _DNS_NAME_MAX or any(len(label) > _DNS_LABEL_MAX for label in zone.split("."))):
            return "invalid_zone", "A DNS name is at most 253 characters, and each of its labels at most 63."
        if zone != account_zone() and _live_names_exist():
            return "live_account_names", "The account zone cannot change while account names are live."
        zone_site = _registrable(zone) if zone else None
        for name in _brand_names():
            if zone_site is not None and zone_site == _registrable(name):
                return (
                    "shares_brand_domain",
                    f"The account zone must be a different registrable domain from {name}: a customer "
                    "site there could set cookies for the brand.",
                )
    elif key == ZONE_ID:
        if str(value or "").strip() != account_zone_id() and _live_names_exist():
            return "live_account_names", "The account zone id cannot change while account names are live."
    elif key == ENABLED and value and not (account_zone() and account_zone_id() and account_zone_api_token()):
        return "hosting_dns_incomplete", "Set the account zone, its id and its API token before turning this on."
    return None
