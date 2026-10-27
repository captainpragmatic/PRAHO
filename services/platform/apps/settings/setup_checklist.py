"""Derived installation requirements with links to their existing owners."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlsplit

from django.conf import settings
from django.core.cache import cache
from django.urls import reverse
from django.utils.translation import get_language
from django.utils.translation import gettext as _

from apps.common.encryption import DecryptionError

from .catalog import CATALOG_BY_KEY
from .services import SettingsService, get_company_legal_name

CACHE_PREFIX = "setup_checklist_v1:"
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SetupItem:
    key: str
    label: str
    description: str
    url: str
    configured: bool
    required: bool = True

    @property
    def action_url(self) -> str:
        return self._return_url("setup")

    @property
    def deployment_action_url(self) -> str:
        return self._return_url("node-deploy")

    def _return_url(self, destination: str) -> str:
        path, separator, anchor = self.url.partition("#")
        return f"{path}{'&' if '?' in path else '?'}return_to={destination}{separator}{anchor}"


@dataclass(frozen=True)
class SetupSection:
    label: str
    items: tuple[SetupItem, ...]


@dataclass(frozen=True)
class SetupReport:
    sections: tuple[SetupSection, ...]

    @property
    def remaining(self) -> int:
        return sum(item.required and not item.configured for section in self.sections for item in section.items)


def setting_url(key: str) -> str:
    definition = CATALOG_BY_KEY[key]
    return f"{reverse('settings:group', args=[definition.group])}#setting-{key}"


def _configured(key: str) -> bool:
    try:
        value = SettingsService.get_setting(key, "")
    except DecryptionError:
        logger.warning("⚠️ [Setup] Stored setting cannot be read: %s", key)
        return False
    return bool(value and (not isinstance(value, str) or (value.strip() and "example.com" not in value)))


def storage_configured() -> bool:
    endpoint = str(SettingsService.get_setting("backup.s3_endpoint_url", "") or "")
    if endpoint:
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
        except ValueError:
            return False
        if (
            parsed.username
            or parsed.password
            or not parsed.hostname
            or parsed.scheme not in {"http", "https"}
            or port == 0
        ):
            return False
        if not settings.DEBUG and (
            parsed.scheme != "https"
            or parsed.hostname in {"localhost", "127.0.0.1", "::1", getattr(settings, "PLATFORM_DOMAIN", "")}
        ):
            return False
    return all(
        _configured(key)
        for key in ("backup.aws_access_key_id", "backup.aws_secret_access_key", "backup.s3_bucket_name")
    )


def get_setup_report() -> SetupReport:
    key = CACHE_PREFIX + str(get_language())
    try:
        cached = cache.get(key)
    except Exception:
        logger.warning("⚠️ [Setup] Checklist cache could not be read")
        cached = None
    if isinstance(cached, SetupReport):
        return cached
    report = evaluate_setup()
    try:
        cache.set(key, report, timeout=30)
    except Exception:
        logger.warning("⚠️ [Setup] Checklist cache could not be written")
    return report


def clear_setup_cache() -> None:
    for language in settings.LANGUAGES:
        try:
            cache.delete(CACHE_PREFIX + language[0])
        except Exception:
            logger.warning("⚠️ [Setup] Checklist cache invalidation failed; the short TTL remains the fallback")


def _email_configured() -> bool:
    from apps.common.system_status_probes import email_probe_config  # noqa: PLC0415

    try:
        provider, configuration = email_probe_config()
    except Exception:
        return False
    if provider == "smtp":
        return bool(
            configuration.get("host") not in {None, "", "localhost", "127.0.0.1", "::1"}
            and bool(configuration.get("username")) == bool(configuration.get("password"))
        )
    if provider in {"sendgrid", "mailgun"}:
        return bool(configuration.get("headers"))
    if provider == "ses":
        # A configured backend may use client keys, a profile, environment or an IAM
        # role. Discovering the default chain can contact metadata servers, so only
        # reject incomplete explicit pairs here; credential verification is health.
        for name in ("session_params", "client_params"):
            parameters = configuration.get(name, {})
            if not isinstance(parameters, dict) or bool(parameters.get("aws_access_key_id")) != bool(
                parameters.get("aws_secret_access_key")
            ):
                return False
        return True
    return False


def evaluate_setup() -> SetupReport:
    from apps.billing.bank_transfer import bank_transfer_instructions  # noqa: PLC0415
    from apps.billing.currency_service import default_selling_currency  # noqa: PLC0415
    from apps.billing.issuers.policy import default_issuer_provider  # noqa: PLC0415
    from apps.common.legal import LegalDocument, current_legal_document  # noqa: PLC0415
    from apps.common.status_models import SystemCheckState  # noqa: PLC0415
    from apps.common.system_status import node_input_identity  # noqa: PLC0415
    from apps.infrastructure.imported_backup_transport import server_transport_ready  # noqa: PLC0415
    from apps.products.models import Product  # noqa: PLC0415
    from apps.provisioning.scheduled_backups import backup_configuration  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

    company = SetupSection(
        _("Business and legal"),
        (
            SetupItem(
                "identity",
                _("Company identity"),
                _(
                    "Review the legal name and registered address. The invoice seller is managed by deployment configuration."
                ),
                setting_url("company.legal_name"),
                bool(get_company_legal_name() and _configured("company.address")),
            ),
            SetupItem(
                "contacts",
                _("Customer contact addresses"),
                _("Replace the example support and privacy email addresses."),
                setting_url("company.email_support"),
                _configured("company.email_support") and _configured("company.email_privacy"),
            ),
            SetupItem(
                "legal",
                _("Publish legal documents"),
                _(
                    "Publish Terms of Service, Privacy Policy and Cookie Policy that are in force in the default language."
                ),
                reverse("settings:legal_documents"),
                all(
                    current_legal_document(kind, settings.LANGUAGE_CODE) is not None
                    for kind in LegalDocument.Kind.values
                ),
            ),
            SetupItem(
                "branding",
                _("Logo and favicon"),
                _("Optional customisation. Brand assets are deployment files; the existing defaults remain usable."),
                setting_url("company.brand_name"),
                bool(getattr(settings, "BRAND_DIR", "")),
                required=False,
            ),
        ),
    )
    issuer = default_issuer_provider()
    payments = bool(bank_transfer_instructions(default_selling_currency())) or bool(
        SettingsService.get_setting("integrations.stripe_enabled", False)
        and all(
            _configured(key)
            for key in (
                "integrations.stripe_secret_key",
                "integrations.stripe_publishable_key",
                "integrations.stripe_webhook_secret",
            )
        )
    )
    billing = SetupSection(
        _("Billing and payments"),
        (
            SetupItem(
                "issuer",
                _("Invoice issuer"),
                _("PRAHO's built-in invoicing is ready by default. External issuers need their own configuration."),
                setting_url("billing.invoice_issuer"),
                issuer == "builtin"
                or all(
                    _configured(key)
                    for key in (
                        "integrations.smartbill_email",
                        "integrations.smartbill_token",
                        "integrations.smartbill_cif",
                        "integrations.smartbill_invoice_series",
                        "integrations.smartbill_tax_names",
                    )
                ),
            ),
            SetupItem(
                "payments",
                _("At least one payment method"),
                _(
                    "Configure bank transfer instructions in the selling currency or enable Stripe with its webhook credentials."
                ),
                setting_url("billing.bank_accounts"),
                payments,
            ),
        ),
    )
    email = SetupSection(
        _("Email"),
        (
            SetupItem(
                "email",
                _("Outbound email"),
                _(
                    "Configure a delivering email backend and sender. Connection and delivery failures appear in System Status."
                ),
                setting_url("company.email_noreply"),
                _configured("company.email_noreply") and _email_configured(),
            ),
        ),
    )
    verified = False
    evidence = {row.node_id: row for row in SystemCheckState.objects.filter(check_key="virtualmin", node__isnull=False)}
    for node in VirtualminServer.objects.all():
        row = evidence.get(node.id)
        if (
            (node.status == "active" or node.failed_by_health_check)
            and row
            and row.verified_generation == row.configuration_generation
            and row.input_identity == node_input_identity(node)
        ):
            verified = True
            break
    sellable = Product.objects.filter(
        product_type="shared_hosting",
        is_active=True,
        is_public=True,
        module="virtualmin",
        default_service_plan__is_active=True,
        prices__is_active=True,
        prices__currency_id=default_selling_currency(),
    ).exists()
    infrastructure = SetupSection(
        _("Hosting"),
        (
            SetupItem(
                "node",
                _("One verified Virtualmin node"),
                _(
                    "Connect an existing server or provision a node. A successful check must verify the current connection settings."
                ),
                reverse("provisioning:virtualmin_servers"),
                verified,
            ),
            SetupItem(
                "plan",
                _("One sellable hosting plan"),
                _(
                    "Publish an active Virtualmin hosting product with a service plan and a price in the selling currency."
                ),
                reverse("products:product_list"),
                sellable,
            ),
            SetupItem(
                "domains",
                _("Domain sales"),
                _("Optional. Configure a registrar and prices if you also sell domains."),
                "/domains/admin/registrars/",
                False,
                required=False,
            ),
        ),
    )
    platform = SystemCheckState.objects.filter(check_key="platform_backup", node__isnull=True).first()
    runner = bool(platform and platform.details.get("runner_enabled") and platform.details.get("configuration_applied"))
    backups = SetupSection(
        _("Backups"),
        (
            SetupItem(
                "backup_transport",
                _("Imported server backup access"),
                _(
                    "Imported servers need an explicit root private key and verified hostname/port entries in known_hosts for backup and restore. Configure these in the deployment environment."
                ),
                reverse("provisioning:virtualmin_servers"),
                all(server_transport_ready(node).is_ok() for node in VirtualminServer.objects.filter(status="active")),
            ),
            SetupItem(
                "platform_backup",
                _("Platform off-server backups"),
                _(
                    "Configure the scheduled database and media backup job and S3 destination. Actual outcomes are shown in System Status."
                ),
                setting_url("backup.platform_offsite_enabled"),
                runner
                and storage_configured()
                and bool(SettingsService.get_setting("backup.platform_offsite_enabled", False)),
            ),
            SetupItem(
                "hosting_backup",
                _("Customer hosting backups"),
                _(
                    "Enable Platform-managed backups with a schedule and S3 storage. Empty nodes have no customer backups due yet."
                ),
                setting_url("node_deployment.backup_storage"),
                backup_configuration()[0],
            ),
        ),
    )
    return SetupReport((company, billing, email, infrastructure, backups))
