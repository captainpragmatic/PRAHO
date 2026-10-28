"""Fail-closed validation for node deployment inputs."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.utils.translation import gettext_lazy as _

from apps.common.encryption import DecryptionError
from apps.common.types import Err, Ok, Result, validate_domain_name

logger = logging.getLogger(__name__)

DNS_ZONE_SETTING_KEY = "node_deployment.dns_default_zone"
MAX_NODE_HOSTNAME_LENGTH = 23
MAX_FQDN_LENGTH = 253
MAX_NODE_DNS_ZONE_LENGTH = MAX_FQDN_LENGTH - MAX_NODE_HOSTNAME_LENGTH - 1
if TYPE_CHECKING:
    from apps.settings.setup_checklist import SetupItem


def deployment_configuration_issues() -> list[SetupItem]:
    """Local, actionable prerequisites for the staff form; execution guards remain authoritative."""
    from django.urls import reverse  # noqa: PLC0415

    from apps.settings.services import SettingsService  # noqa: PLC0415
    from apps.settings.setup_checklist import SetupItem, setting_url  # noqa: PLC0415

    from .ansible_service import AnsibleService, node_admin_allowed_cidrs  # noqa: PLC0415
    from .models import CloudProvider  # noqa: PLC0415

    issues = []
    if not SettingsService.get_setting("node_deployment.enabled", True):
        issues.append(
            SetupItem(
                "enabled",
                str(_("Enable node deployment")),
                str(_("An administrator has disabled new node deployments.")),
                setting_url("node_deployment.enabled"),
                False,
            )
        )
    zone = str(SettingsService.get_setting(DNS_ZONE_SETTING_KEY, "") or "")
    if validate_deployment_dns_zone(zone).is_err():
        issues.append(
            SetupItem(
                "dns",
                str(_("DNS default zone")),
                str(_("Choose a valid domain suffix for node hostnames, such as nodes.example.com.")),
                setting_url(DNS_ZONE_SETTING_KEY),
                False,
            )
        )
    for key, label in (
        ("node_deployment.dns_cloudflare_api_token", _("Cloudflare API token")),
        ("node_deployment.dns_cloudflare_zone_id", _("Cloudflare zone ID")),
    ):
        try:
            configured = bool(SettingsService.get_setting(key, ""))
        except DecryptionError:
            logger.warning("⚠️ [Deployment] Stored setting cannot be read: %s", key)
            configured = False
        if not configured:
            issues.append(
                SetupItem(
                    key,
                    str(label),
                    str(_("Configure the Cloudflare zone used to publish node DNS records.")),
                    setting_url(key),
                    False,
                )
            )
    try:
        networks = node_admin_allowed_cidrs()
    except ValueError:
        networks = []
    if not networks:
        issues.append(
            SetupItem(
                "networks",
                str(_("Node admin allowlist")),
                str(_("Include Platform's egress address and the operators' administration networks.")),
                setting_url("infrastructure.node_admin_allowed_cidrs"),
                False,
            )
        )
    try:
        AnsibleService.operator_public_keys()
    except (OSError, ValueError):
        issues.append(
            SetupItem(
                "keys",
                str(_("Approved operator SSH keys")),
                str(
                    _(
                        "The deployment operator must configure PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE with the approved public keys."
                    )
                ),
                reverse("settings:group", args=["node-deployment"]),
                False,
            )
        )
    if not CloudProvider.objects.filter(is_active=True, provider_type="hetzner").exists():
        issues.append(
            SetupItem(
                "provider",
                str(_("Supported cloud provider")),
                str(
                    _(
                        "Add an active Hetzner provider. Automatic node deployment currently supports its Ubuntu 26.04 image."
                    )
                ),
                reverse("infrastructure:provider_list"),
                False,
            )
        )
    return issues


def validate_deployment_dns_zone(dns_zone: str) -> Result[str, str]:
    """Return a normalized DNS zone suitable for constructing node FQDNs."""
    raw_zone = str(dns_zone or "")
    normalized_zone = raw_zone.strip().lower()
    if not normalized_zone:
        return Err(
            str(
                _("Node deployment requires a fully-qualified hostname; configure %(key)s before deploying.")
                % {"key": DNS_ZONE_SETTING_KEY}
            )
        )
    if raw_zone != raw_zone.strip():
        return Err(str(_("Node deployment DNS zone is invalid: surrounding whitespace is not allowed.")))
    if len(normalized_zone) > MAX_NODE_DNS_ZONE_LENGTH:
        return Err(str(_("Node deployment DNS zone is too long for the generated node hostname.")))

    result = validate_domain_name(normalized_zone)
    if result.is_err():
        return Err(str(_("Node deployment DNS zone is invalid: %(error)s.") % {"error": result.unwrap_err()}))
    return Ok(str(result.unwrap()))


def validate_deployment_fqdn(hostname: str, dns_zone: str) -> Result[str, str]:
    """Validate and return the canonical FQDN used by Virtualmin and DNS."""
    zone_result = validate_deployment_dns_zone(dns_zone)
    if zone_result.is_err():
        return Err(zone_result.unwrap_err())

    fqdn_result = validate_domain_name(f"{hostname.strip().lower()}.{zone_result.unwrap()}")
    if fqdn_result.is_err():
        return Err(
            str(
                _("Node deployment fully-qualified hostname is invalid: %(error)s.")
                % {"error": fqdn_result.unwrap_err()}
            )
        )
    return Ok(str(fqdn_result.unwrap()))
