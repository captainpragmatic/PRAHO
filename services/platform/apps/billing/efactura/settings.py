"""
e-Factura configurable settings for production-grade compliance.

All settings are configurable via the SystemSetting database model,
with sensible defaults and type validation.

Usage:
    from apps.billing.efactura.settings import EFacturaSettings

    settings = EFacturaSettings()
    vat_rate = settings.get_vat_rate('standard')
    api_url = settings.api_base_url
"""

from __future__ import annotations

import logging
import zoneinfo
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from functools import cached_property
from typing import TYPE_CHECKING, Any

from django.conf import settings as django_settings
from django.utils import timezone

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# ===============================================================================
# CONSTANTS - These are fixed by ANAF/EU regulations and cannot be configured
# ===============================================================================

# CIUS-RO version (updated by ANAF, not configurable)
CIUS_RO_VERSION = "1.0.1"
CIUS_RO_CUSTOMIZATION_ID = f"urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:{CIUS_RO_VERSION}"

# PEPPOL BIS Billing 3.0 Profile (EU standard)
PEPPOL_PROFILE_ID = "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0"

# UBL 2.1 Namespaces (fixed by OASIS standard)
UBL_NAMESPACES = {
    "ubl": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cn": "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2",
}

# Invoice type codes (UNCL1001 - UN/CEFACT standard)
INVOICE_TYPE_CODES = {
    "commercial": "380",
    "credit_note": "381",
    "debit_note": "383",
    "prepayment": "386",
    "self_billed": "389",
}

# Unit codes (UN/ECE Recommendation 20)
UNIT_CODES = {
    "piece": "C62",
    "hour": "HUR",
    "day": "DAY",
    "month": "MON",
    "year": "ANN",
    "kilogram": "KGM",
    "meter": "MTR",
    "liter": "LTR",
    "square_meter": "MTK",
    "cubic_meter": "MTQ",
}

# Romanian timezone (required by ANAF)
ROMANIA_TIMEZONE = zoneinfo.ZoneInfo("Europe/Bucharest")


class VATCategory(StrEnum):
    """VAT category codes per UNCL5305."""

    STANDARD = "S"  # Standard rate
    ZERO = "Z"  # Zero rated goods
    EXEMPT = "E"  # Exempt from tax
    REVERSE_CHARGE = "AE"  # VAT Reverse Charge
    NOT_SUBJECT = "O"  # Services outside scope of tax
    INTRA_COMMUNITY = "K"  # Intra-community supply
    EXPORT = "G"  # Free export item

    @classmethod
    def choices(cls) -> list[tuple[str, str]]:
        return [(c.value, c.name.replace("_", " ").title()) for c in cls]


class EFacturaEnvironment(StrEnum):
    """ANAF API environments."""

    TEST = "test"
    PRODUCTION = "production"

    @property
    def api_base_url(self) -> str:
        urls = {
            "test": "https://api.anaf.ro/test/FCTEL/rest",
            "production": "https://api.anaf.ro/prod/FCTEL/rest",
        }
        return urls[self.value]

    @property
    def oauth_base_url(self) -> str:
        return "https://logincert.anaf.ro/anaf-oauth2/v1"


# ===============================================================================
# SETTING KEYS - All configurable e-Factura settings
# ===============================================================================


class EFacturaSettingKeys:
    """Setting keys for e-Factura configuration."""

    # General
    ENABLED = "efactura.enabled"
    ENVIRONMENT = "efactura.environment"

    # OAuth2 credentials
    CLIENT_ID = "efactura.oauth.client_id"
    CLIENT_SECRET = "efactura.oauth.client_secret"  # noqa: S105
    REDIRECT_URI = "efactura.oauth.redirect_uri"

    # Company information
    COMPANY_CUI = "efactura.company.cui"
    COMPANY_NAME = "efactura.company.name"
    COMPANY_REGISTRATION = "efactura.company.registration_number"
    COMPANY_STREET = "efactura.company.street"
    COMPANY_CITY = "efactura.company.city"
    COMPANY_POSTAL_CODE = "efactura.company.postal_code"
    COMPANY_COUNTRY = "efactura.company.country_code"
    COMPANY_EMAIL = "efactura.company.email"
    COMPANY_PHONE = "efactura.company.phone"
    COMPANY_BANK_ACCOUNT = "efactura.company.bank_account"
    COMPANY_BANK_NAME = "efactura.company.bank_name"

    # VAT rates (Romanian rates as of Aug 2025)
    VAT_RATE_STANDARD = "efactura.vat.rate_standard"
    VAT_RATE_REDUCED_1 = "efactura.vat.rate_reduced_1"  # 11% (consolidated)
    VAT_RATE_REDUCED_2 = "efactura.vat.rate_reduced_2"  # 11% (consolidated)
    VAT_RATE_ZERO = "efactura.vat.rate_zero"

    # B2B/B2C settings
    B2B_ENABLED = "efactura.b2b.enabled"
    B2C_ENABLED = "efactura.b2c.enabled"
    B2C_MINIMUM_AMOUNT = "efactura.b2c.minimum_amount_cents"
    B2B_MINIMUM_AMOUNT = "efactura.b2b.minimum_amount_cents"

    # Submission settings
    SUBMISSION_DEADLINE_DAYS = "efactura.submission.deadline_days"
    DEADLINE_WARNING_HOURS = "efactura.submission.deadline_warning_hours"
    AUTO_SUBMIT_ENABLED = "efactura.submission.auto_submit_enabled"

    # Retry configuration
    MAX_RETRIES = "efactura.retry.max_retries"
    RETRY_DELAY_1 = "efactura.retry.delay_1_seconds"
    RETRY_DELAY_2 = "efactura.retry.delay_2_seconds"
    RETRY_DELAY_3 = "efactura.retry.delay_3_seconds"
    RETRY_DELAY_4 = "efactura.retry.delay_4_seconds"
    RETRY_DELAY_5 = "efactura.retry.delay_5_seconds"

    # API rate limits (per ANAF documentation)
    RATE_LIMIT_GLOBAL_PER_MINUTE = "efactura.rate_limit.global_per_minute"
    RATE_LIMIT_STATUS_PER_MESSAGE_DAY = "efactura.rate_limit.status_per_message_day"
    RATE_LIMIT_LIST_SIMPLE_PER_DAY = "efactura.rate_limit.list_simple_per_day"
    RATE_LIMIT_LIST_PAGINATED_PER_DAY = "efactura.rate_limit.list_paginated_per_day"
    RATE_LIMIT_DOWNLOAD_PER_MESSAGE_DAY = "efactura.rate_limit.download_per_message_day"

    # Polling settings
    POLL_INTERVAL_SECONDS = "efactura.polling.interval_seconds"
    POLL_BATCH_SIZE = "efactura.polling.batch_size"
    STALE_SUBMISSION_HOURS = "efactura.polling.stale_submission_hours"

    # Validation settings
    XSD_VALIDATION_ENABLED = "efactura.validation.xsd_enabled"
    SCHEMATRON_VALIDATION_ENABLED = "efactura.validation.schematron_enabled"
    STRICT_MODE = "efactura.validation.strict_mode"

    # Storage settings
    XML_STORAGE_PATH = "efactura.storage.xml_path"
    PDF_STORAGE_PATH = "efactura.storage.pdf_path"
    ARCHIVE_RETENTION_YEARS = "efactura.storage.archive_retention_years"

    # Metrics/observability
    METRICS_ENABLED = "efactura.metrics.enabled"
    METRICS_PREFIX = "efactura.metrics.prefix"


# ===============================================================================
# DEFAULT VALUES
# ===============================================================================

EFACTURA_DEFAULTS: dict[str, Any] = {
    # General
    EFacturaSettingKeys.ENABLED: True,
    EFacturaSettingKeys.ENVIRONMENT: "test",
    # OAuth2 (must be configured)
    EFacturaSettingKeys.CLIENT_ID: "",
    EFacturaSettingKeys.CLIENT_SECRET: "",
    EFacturaSettingKeys.REDIRECT_URI: "",
    # Company (must be configured)
    EFacturaSettingKeys.COMPANY_CUI: "",
    EFacturaSettingKeys.COMPANY_NAME: "",
    EFacturaSettingKeys.COMPANY_REGISTRATION: "",
    EFacturaSettingKeys.COMPANY_STREET: "",
    EFacturaSettingKeys.COMPANY_CITY: "",
    EFacturaSettingKeys.COMPANY_POSTAL_CODE: "",
    EFacturaSettingKeys.COMPANY_COUNTRY: "RO",
    EFacturaSettingKeys.COMPANY_EMAIL: "",
    EFacturaSettingKeys.COMPANY_PHONE: "",
    EFacturaSettingKeys.COMPANY_BANK_ACCOUNT: "",
    EFacturaSettingKeys.COMPANY_BANK_NAME: "",
    # Romanian VAT rates (updated Aug 2025 — Emergency Ordinance 156/2024)
    EFacturaSettingKeys.VAT_RATE_STANDARD: "21.00",  # Standard rate (was 19%)
    EFacturaSettingKeys.VAT_RATE_REDUCED_1: "11.00",  # Consolidated reduced rate (was 9%)
    EFacturaSettingKeys.VAT_RATE_REDUCED_2: "11.00",  # Consolidated reduced rate (was 5%)
    EFacturaSettingKeys.VAT_RATE_ZERO: "0.00",  # Exports, intra-EU supplies
    # B2B/B2C
    EFacturaSettingKeys.B2B_ENABLED: True,
    EFacturaSettingKeys.B2C_ENABLED: False,  # Mandatory from Jan 2025
    EFacturaSettingKeys.B2C_MINIMUM_AMOUNT: 0,
    EFacturaSettingKeys.B2B_MINIMUM_AMOUNT: 0,
    # Submission (5 calendar days per Romanian law)
    EFacturaSettingKeys.SUBMISSION_DEADLINE_DAYS: 5,
    EFacturaSettingKeys.DEADLINE_WARNING_HOURS: 24,
    EFacturaSettingKeys.AUTO_SUBMIT_ENABLED: True,
    # Retry with exponential backoff
    EFacturaSettingKeys.MAX_RETRIES: 5,
    EFacturaSettingKeys.RETRY_DELAY_1: 300,  # 5 minutes
    EFacturaSettingKeys.RETRY_DELAY_2: 900,  # 15 minutes
    EFacturaSettingKeys.RETRY_DELAY_3: 3600,  # 1 hour
    EFacturaSettingKeys.RETRY_DELAY_4: 7200,  # 2 hours
    EFacturaSettingKeys.RETRY_DELAY_5: 21600,  # 6 hours
    # ANAF API rate limits (per official documentation)
    EFacturaSettingKeys.RATE_LIMIT_GLOBAL_PER_MINUTE: 1000,
    EFacturaSettingKeys.RATE_LIMIT_STATUS_PER_MESSAGE_DAY: 100,
    EFacturaSettingKeys.RATE_LIMIT_LIST_SIMPLE_PER_DAY: 1500,
    EFacturaSettingKeys.RATE_LIMIT_LIST_PAGINATED_PER_DAY: 100000,
    EFacturaSettingKeys.RATE_LIMIT_DOWNLOAD_PER_MESSAGE_DAY: 10,
    # Polling
    EFacturaSettingKeys.POLL_INTERVAL_SECONDS: 300,  # 5 minutes
    EFacturaSettingKeys.POLL_BATCH_SIZE: 100,
    EFacturaSettingKeys.STALE_SUBMISSION_HOURS: 24,
    # Validation
    EFacturaSettingKeys.XSD_VALIDATION_ENABLED: True,
    EFacturaSettingKeys.SCHEMATRON_VALIDATION_ENABLED: True,
    EFacturaSettingKeys.STRICT_MODE: False,
    # Storage
    EFacturaSettingKeys.XML_STORAGE_PATH: "efactura/xml/%Y/%m/",
    EFacturaSettingKeys.PDF_STORAGE_PATH: "efactura/pdf/%Y/%m/",
    EFacturaSettingKeys.ARCHIVE_RETENTION_YEARS: 10,  # Romanian law requires 10 years
    # Metrics
    EFacturaSettingKeys.METRICS_ENABLED: True,
    EFacturaSettingKeys.METRICS_PREFIX: "efactura",
}


# ===============================================================================
# VAT RATE CONFIGURATION
# ===============================================================================


@dataclass
class VATRateConfig:
    """Configuration for a VAT rate."""

    rate: Decimal
    category: VATCategory
    name: str
    description: str = ""
    applies_to: list[str] = field(default_factory=list)

    @property
    def rate_percent(self) -> Decimal:
        """Get rate as percentage (e.g., 19 for 19%)."""
        return self.rate

    @property
    def rate_decimal(self) -> Decimal:
        """Get rate as decimal (e.g., 0.19 for 19%)."""
        return self.rate / Decimal("100")


# Romanian VAT rates with categories
ROMANIAN_VAT_RATES: dict[str, VATRateConfig] = {
    "standard": VATRateConfig(
        rate=Decimal("21.00"),
        category=VATCategory.STANDARD,
        name="Standard Rate",
        description="Standard Romanian VAT rate (updated Aug 2025)",
        applies_to=["general", "services", "goods"],
    ),
    "reduced": VATRateConfig(
        rate=Decimal("11.00"),
        category=VATCategory.STANDARD,
        name="Reduced Rate (11%)",
        description="Consolidated reduced rate: hospitality, food, books, medicine, housing",
        applies_to=[
            "hospitality",
            "culture",
            "sports",
            "food_service",
            "food",
            "books",
            "medicine",
            "housing",
            "prosthetics",
        ],
    ),
    "zero": VATRateConfig(
        rate=Decimal("0.00"),
        category=VATCategory.ZERO,
        name="Zero Rate",
        description="Exports, intra-EU supplies with valid VAT",
        applies_to=["export", "intra_eu"],
    ),
    "exempt": VATRateConfig(
        rate=Decimal("0.00"),
        category=VATCategory.EXEMPT,
        name="Exempt",
        description="Medical, education, financial services, insurance",
        applies_to=["medical", "education", "financial", "insurance"],
    ),
    "reverse_charge": VATRateConfig(
        rate=Decimal("0.00"),
        category=VATCategory.REVERSE_CHARGE,
        name="Reverse Charge",
        description="B2B intra-EU services, domestic reverse charge",
        applies_to=["intra_eu_b2b", "construction", "scrap"],
    ),
}


# ===============================================================================
# SETTINGS SERVICE
# ===============================================================================


class EFacturaSettings:
    """
    Production-grade e-Factura settings service.

    Provides type-safe access to all e-Factura configuration with:
    - Database-backed settings via SystemSetting model
    - Fallback to Django settings
    - Caching for performance
    - VAT rate management
    - Quota tracking
    """

    CACHE_PREFIX = "efactura_settings"
    CACHE_TIMEOUT = 300  # 5 minutes

    def __init__(self) -> None:
        self._settings_service = None
        self._vat_rates: dict[str, VATRateConfig] = {}

    @property
    def settings_service(self) -> Any:
        """Lazy load SettingsService to avoid circular imports."""
        if self._settings_service is None:
            try:
                from apps.settings.services import SettingsService  # noqa: PLC0415

                self._settings_service = SettingsService
            except ImportError:
                logger.warning("SettingsService not available, using Django settings fallback")
                self._settings_service = None
        return self._settings_service

    def _get_setting(self, key: str, default: Any = None) -> Any:
        """Get setting with fallback chain: DB -> Django settings -> default."""
        # Try database settings first
        if self.settings_service:
            try:
                value = self.settings_service.get_setting(key, None)
                if value is not None:
                    return value
            except Exception as e:
                logger.debug(f"Could not get {key} from SettingsService: {e}")

        # Try Django settings
        django_key = key.replace(".", "_").upper()
        django_value = getattr(django_settings, django_key, None)
        if django_value is not None:
            return django_value

        # Return default
        return EFACTURA_DEFAULTS.get(key, default)

    def _get_string(self, key: str, default: str = "") -> str:
        """Get string setting."""
        value = self._get_setting(key, default)
        return str(value) if value is not None else default

    def _get_int(self, key: str, default: int = 0) -> int:
        """Get integer setting."""
        value = self._get_setting(key, default)
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def _get_bool(self, key: str, default: bool = False) -> bool:
        """Get boolean setting."""
        value = self._get_setting(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes", "on")
        return bool(value)

    def _get_decimal(self, key: str, default: str = "0") -> Decimal:
        """Get decimal setting."""
        value = self._get_setting(key, default)
        try:
            return Decimal(str(value))
        except Exception:
            return Decimal(default)

    # ===== General Settings =====

    @property
    def enabled(self) -> bool:
        """Check if e-Factura is enabled."""
        return self._get_bool(EFacturaSettingKeys.ENABLED, True)

    @property
    def environment(self) -> EFacturaEnvironment:
        """Get current environment (test/production)."""
        env = self._get_string(EFacturaSettingKeys.ENVIRONMENT, "test")
        try:
            return EFacturaEnvironment(env)
        except ValueError:
            return EFacturaEnvironment.TEST

    @property
    def api_base_url(self) -> str:
        """Get ANAF API base URL for current environment."""
        return self.environment.api_base_url

    @property
    def oauth_base_url(self) -> str:
        """Get OAuth base URL."""
        return self.environment.oauth_base_url

    # ===== OAuth2 Settings =====

    @property
    def client_id(self) -> str:
        """Get OAuth2 client ID."""
        return self._get_string(EFacturaSettingKeys.CLIENT_ID)

    @property
    def client_secret(self) -> str:
        """Get OAuth2 client secret."""
        return self._get_string(EFacturaSettingKeys.CLIENT_SECRET)

    @property
    def redirect_uri(self) -> str:
        """Get OAuth2 redirect URI."""
        return self._get_string(EFacturaSettingKeys.REDIRECT_URI)

    # ===== Company Settings =====

    @property
    def company_cui(self) -> str:
        """Get company CUI (tax ID)."""
        return self._get_string(EFacturaSettingKeys.COMPANY_CUI)

    @property
    def company_name(self) -> str:
        """Get company name."""
        return self._get_string(EFacturaSettingKeys.COMPANY_NAME)

    @property
    def company_registration(self) -> str:
        """Get company registration number (J number)."""
        return self._get_string(EFacturaSettingKeys.COMPANY_REGISTRATION)

    @property
    def company_vat_number(self) -> str:
        """Get full VAT number with RO prefix."""
        cui = self.company_cui
        if cui and not cui.startswith("RO"):
            return f"RO{cui}"
        return cui

    @cached_property
    def company_address(self) -> dict[str, str]:
        """Get company address as dictionary."""
        return {
            "street": self._get_string(EFacturaSettingKeys.COMPANY_STREET),
            "city": self._get_string(EFacturaSettingKeys.COMPANY_CITY),
            "postal_code": self._get_string(EFacturaSettingKeys.COMPANY_POSTAL_CODE),
            "country_code": self._get_string(EFacturaSettingKeys.COMPANY_COUNTRY, "RO"),
        }

    @property
    def company_email(self) -> str:
        """Get company email."""
        return self._get_string(EFacturaSettingKeys.COMPANY_EMAIL)

    @property
    def company_phone(self) -> str:
        """Get company phone."""
        return self._get_string(EFacturaSettingKeys.COMPANY_PHONE)

    @property
    def company_bank_account(self) -> str:
        """Get company bank account (IBAN)."""
        return self._get_string(EFacturaSettingKeys.COMPANY_BANK_ACCOUNT)

    @property
    def company_bank_name(self) -> str:
        """Get company bank name."""
        return self._get_string(EFacturaSettingKeys.COMPANY_BANK_NAME)

    # ===== VAT Rate Settings =====

    def get_vat_rate(self, rate_type: str = "standard") -> VATRateConfig:
        """
        Get VAT rate configuration by type.

        Args:
            rate_type: One of 'standard', 'reduced_9', 'reduced_5', 'zero', 'exempt', 'reverse_charge'

        Returns:
            VATRateConfig with rate and category
        """
        # Check for custom rates in settings
        rate_key_map = {
            "standard": EFacturaSettingKeys.VAT_RATE_STANDARD,
            "reduced": EFacturaSettingKeys.VAT_RATE_REDUCED_1,
            "reduced_9": EFacturaSettingKeys.VAT_RATE_REDUCED_1,  # legacy alias
            "reduced_5": EFacturaSettingKeys.VAT_RATE_REDUCED_2,  # legacy alias
            "zero": EFacturaSettingKeys.VAT_RATE_ZERO,
        }

        if rate_type in rate_key_map:
            custom_rate = self._get_decimal(rate_key_map[rate_type])
            base_config = ROMANIAN_VAT_RATES.get(rate_type, ROMANIAN_VAT_RATES["standard"])
            return VATRateConfig(
                rate=custom_rate,
                category=base_config.category,
                name=base_config.name,
                description=base_config.description,
                applies_to=base_config.applies_to,
            )

        return ROMANIAN_VAT_RATES.get(rate_type, ROMANIAN_VAT_RATES["standard"])

    def get_vat_rate_for_category(self, category: str) -> VATRateConfig:
        """
        Get appropriate VAT rate for a product/service category.

        Args:
            category: Product/service category (e.g., 'food', 'hospitality', 'medical')

        Returns:
            Appropriate VATRateConfig for the category
        """
        for rate_type, config in ROMANIAN_VAT_RATES.items():
            if category.lower() in config.applies_to:
                return self.get_vat_rate(rate_type)
        return self.get_vat_rate("standard")

    @property
    def standard_vat_rate(self) -> Decimal:
        """Get standard VAT rate as decimal."""
        return self.get_vat_rate("standard").rate

    # ===== B2B/B2C Settings =====

    @property
    def b2b_enabled(self) -> bool:
        """Check if B2B e-Factura is enabled."""
        return self._get_bool(EFacturaSettingKeys.B2B_ENABLED, True)

    @property
    def b2c_enabled(self) -> bool:
        """Check if B2C e-Factura is enabled."""
        return self._get_bool(EFacturaSettingKeys.B2C_ENABLED, False)

    @property
    def b2b_minimum_amount_cents(self) -> int:
        """Minimum amount in cents for B2B e-Factura."""
        return self._get_int(EFacturaSettingKeys.B2B_MINIMUM_AMOUNT, 0)

    @property
    def b2c_minimum_amount_cents(self) -> int:
        """Minimum amount in cents for B2C e-Factura."""
        return self._get_int(EFacturaSettingKeys.B2C_MINIMUM_AMOUNT, 0)

    # ===== Submission Settings =====

    @property
    def submission_deadline_days(self) -> int:
        """Get submission deadline in calendar days (default: 5)."""
        return self._get_int(EFacturaSettingKeys.SUBMISSION_DEADLINE_DAYS, 5)

    @property
    def deadline_warning_hours(self) -> int:
        """Hours before deadline to trigger warning."""
        return self._get_int(EFacturaSettingKeys.DEADLINE_WARNING_HOURS, 24)

    @property
    def auto_submit_enabled(self) -> bool:
        """Check if auto-submission is enabled."""
        return self._get_bool(EFacturaSettingKeys.AUTO_SUBMIT_ENABLED, True)

    # ===== Retry Settings =====

    @property
    def max_retries(self) -> int:
        """Maximum number of retry attempts."""
        return self._get_int(EFacturaSettingKeys.MAX_RETRIES, 5)

    @property
    def retry_delays(self) -> list[int]:
        """Get list of retry delays in seconds."""
        return [
            self._get_int(EFacturaSettingKeys.RETRY_DELAY_1, 300),
            self._get_int(EFacturaSettingKeys.RETRY_DELAY_2, 900),
            self._get_int(EFacturaSettingKeys.RETRY_DELAY_3, 3600),
            self._get_int(EFacturaSettingKeys.RETRY_DELAY_4, 7200),
            self._get_int(EFacturaSettingKeys.RETRY_DELAY_5, 21600),
        ]

    def get_retry_delay(self, attempt: int) -> int:
        """Get delay in seconds for a specific retry attempt."""
        delays = self.retry_delays
        index = min(attempt - 1, len(delays) - 1)
        return delays[index] if index >= 0 else delays[0]

    # ===== Rate Limit Settings =====

    @property
    def rate_limit_global_per_minute(self) -> int:
        """Global API rate limit per minute."""
        return self._get_int(EFacturaSettingKeys.RATE_LIMIT_GLOBAL_PER_MINUTE, 1000)

    @property
    def rate_limit_status_per_message_day(self) -> int:
        """Max status queries per message per day."""
        return self._get_int(EFacturaSettingKeys.RATE_LIMIT_STATUS_PER_MESSAGE_DAY, 100)

    @property
    def rate_limit_list_simple_per_day(self) -> int:
        """Max simple list queries per CUI per day."""
        return self._get_int(EFacturaSettingKeys.RATE_LIMIT_LIST_SIMPLE_PER_DAY, 1500)

    @property
    def rate_limit_list_paginated_per_day(self) -> int:
        """Max paginated list queries per CUI per day."""
        return self._get_int(EFacturaSettingKeys.RATE_LIMIT_LIST_PAGINATED_PER_DAY, 100000)

    @property
    def rate_limit_download_per_message_day(self) -> int:
        """Max downloads per message per day."""
        return self._get_int(EFacturaSettingKeys.RATE_LIMIT_DOWNLOAD_PER_MESSAGE_DAY, 10)

    # ===== Polling Settings =====

    @property
    def poll_interval_seconds(self) -> int:
        """Polling interval in seconds."""
        return self._get_int(EFacturaSettingKeys.POLL_INTERVAL_SECONDS, 300)

    @property
    def poll_batch_size(self) -> int:
        """Number of documents to poll per batch."""
        return self._get_int(EFacturaSettingKeys.POLL_BATCH_SIZE, 100)

    @property
    def stale_submission_hours(self) -> int:
        """Hours after which a submission is considered stale."""
        return self._get_int(EFacturaSettingKeys.STALE_SUBMISSION_HOURS, 24)

    # ===== Validation Settings =====

    @property
    def xsd_validation_enabled(self) -> bool:
        """Check if XSD validation is enabled."""
        return self._get_bool(EFacturaSettingKeys.XSD_VALIDATION_ENABLED, True)

    @property
    def schematron_validation_enabled(self) -> bool:
        """Check if Schematron validation is enabled."""
        return self._get_bool(EFacturaSettingKeys.SCHEMATRON_VALIDATION_ENABLED, True)

    @property
    def strict_mode(self) -> bool:
        """Check if strict validation mode is enabled."""
        return self._get_bool(EFacturaSettingKeys.STRICT_MODE, False)

    # ===== Storage Settings =====

    @property
    def xml_storage_path(self) -> str:
        """Get XML storage path template."""
        return self._get_string(EFacturaSettingKeys.XML_STORAGE_PATH, "efactura/xml/%Y/%m/")

    @property
    def pdf_storage_path(self) -> str:
        """Get PDF storage path template."""
        return self._get_string(EFacturaSettingKeys.PDF_STORAGE_PATH, "efactura/pdf/%Y/%m/")

    @property
    def archive_retention_years(self) -> int:
        """Archive retention period in years (Romanian law: 10 years)."""
        return self._get_int(EFacturaSettingKeys.ARCHIVE_RETENTION_YEARS, 10)

    # ===== Metrics Settings =====

    @property
    def metrics_enabled(self) -> bool:
        """Check if metrics collection is enabled."""
        return self._get_bool(EFacturaSettingKeys.METRICS_ENABLED, True)

    @property
    def metrics_prefix(self) -> str:
        """Get metrics prefix."""
        return self._get_string(EFacturaSettingKeys.METRICS_PREFIX, "efactura")

    # ===== Utility Methods =====

    def get_romania_now(self) -> datetime:
        """Get current time in Romanian timezone."""
        return timezone.now().astimezone(ROMANIA_TIMEZONE)

    def to_romania_time(self, dt: datetime) -> datetime:
        """Convert datetime to Romanian timezone."""
        return dt.astimezone(ROMANIA_TIMEZONE)

    def calculate_deadline(self, issued_at: datetime) -> datetime:
        """Calculate submission deadline from issue date."""
        return issued_at + timedelta(days=self.submission_deadline_days)

    def is_deadline_approaching(self, issued_at: datetime) -> bool:
        """Check if submission deadline is approaching."""
        deadline = self.calculate_deadline(issued_at)
        warning_time = deadline - timedelta(hours=self.deadline_warning_hours)
        return self.get_romania_now() >= warning_time

    def is_deadline_passed(self, issued_at: datetime) -> bool:
        """Check if submission deadline has passed."""
        deadline = self.calculate_deadline(issued_at)
        return self.get_romania_now() > deadline

    def is_configured(self) -> bool:
        """Check if minimum required settings are configured."""
        required = [
            self.company_cui,
            self.company_name,
            self.client_id,
        ]
        return all(required)

    def validate_configuration(self) -> list[str]:
        """Validate configuration and return list of issues."""
        issues = []

        if not self.company_cui:
            issues.append("Company CUI is not configured")
        if not self.company_name:
            issues.append("Company name is not configured")
        if not self.client_id:
            issues.append("OAuth client ID is not configured")
        if not self.client_secret:
            issues.append("OAuth client secret is not configured")
        if not self.company_address.get("street"):
            issues.append("Company street address is not configured")
        if not self.company_address.get("city"):
            issues.append("Company city is not configured")

        return issues


# Global settings instance
efactura_settings = EFacturaSettings()
