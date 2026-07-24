"""Fail-closed validation for node deployment inputs."""

from __future__ import annotations

from apps.common.types import Err, Ok, Result, validate_domain_name

DNS_ZONE_SETTING_KEY = "node_deployment.dns_default_zone"
MAX_NODE_HOSTNAME_LENGTH = 23
MAX_FQDN_LENGTH = 253
MAX_NODE_DNS_ZONE_LENGTH = MAX_FQDN_LENGTH - MAX_NODE_HOSTNAME_LENGTH - 1


def validate_deployment_dns_zone(dns_zone: str) -> Result[str, str]:
    """Return a normalized DNS zone suitable for constructing node FQDNs."""
    raw_zone = str(dns_zone or "")
    normalized_zone = raw_zone.strip().lower()
    if not normalized_zone:
        return Err(
            f"Node deployment requires a fully-qualified hostname; configure {DNS_ZONE_SETTING_KEY} before deploying."
        )
    if raw_zone != raw_zone.strip():
        return Err("Node deployment DNS zone is invalid: surrounding whitespace is not allowed.")
    if len(normalized_zone) > MAX_NODE_DNS_ZONE_LENGTH:
        return Err("Node deployment DNS zone is too long for the generated node hostname.")

    result = validate_domain_name(normalized_zone)
    if result.is_err():
        return Err(f"Node deployment DNS zone is invalid: {result.unwrap_err()}.")
    return Ok(str(result.unwrap()))


def validate_deployment_fqdn(hostname: str, dns_zone: str) -> Result[str, str]:
    """Validate and return the canonical FQDN used by Virtualmin and DNS."""
    zone_result = validate_deployment_dns_zone(dns_zone)
    if zone_result.is_err():
        return Err(zone_result.unwrap_err())

    fqdn_result = validate_domain_name(f"{hostname.strip().lower()}.{zone_result.unwrap()}")
    if fqdn_result.is_err():
        return Err(f"Node deployment fully-qualified hostname is invalid: {fqdn_result.unwrap_err()}.")
    return Ok(str(fqdn_result.unwrap()))
