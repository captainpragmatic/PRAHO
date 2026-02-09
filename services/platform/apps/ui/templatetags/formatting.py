"""
PRAHO PLATFORM - Romanian Formatting Template Tags
===============================================================================
Romanian business formatting for dates, currency, legal compliance
"""

import decimal
import re
from decimal import Decimal
from typing import Any

from django import template
from django.utils import timezone
from django.utils.html import escape  # For XSS prevention
from django.utils.safestring import SafeString, mark_safe

from apps.common.constants import (
    PHONE_LANDLINE_LENGTH,
    PHONE_MIN_VALID_LENGTH,
    PHONE_MOBILE_LENGTH,
    ROMANIAN_IBAN_LENGTH,
    ROMANIAN_PLURAL_FEW_MAX,
    ROMANIAN_PLURAL_FEW_MIN,
    ROMANIAN_PLURAL_SINGLE,
    ROMANIAN_POSTAL_CODE_LENGTH,
    ROMANIAN_TIME_HOUR_PLURAL_THRESHOLD,
    ROMANIAN_TIME_MINUTE_PLURAL_THRESHOLD,
    SECONDS_PER_DAY,
    SECONDS_PER_HOUR,
    SECONDS_PER_MINUTE,
    SECONDS_PER_TWO_DAYS,
    SECONDS_PER_WEEK,
)

register = template.Library()

# Type alias for common template filter numeric inputs
TemplateNumeric = int | float | Decimal | None


def validate_template_numeric(value: TemplateNumeric, default_message: str = "0,00") -> tuple[bool, str]:
    """
    Validate template numeric input and return appropriate default.

    Returns:
        tuple: (is_valid, default_value_if_invalid)
    """
    if value is None:
        return False, default_message
    return True, ""


@register.filter
def romanian_currency(value: TemplateNumeric, currency: str = "RON") -> str:
    """
    Format currency in Romanian business style

    Usage:
        {{ invoice.total|romanian_currency }}     -> "1.234,56 RON"
        {{ amount|romanian_currency:"EUR" }}     -> "1.234,56 EUR"
        {{ hosting_price|romanian_currency }}    -> "49,99 RON"

    Args:
        value: Numeric value to format
        currency: Currency code (RON, EUR, USD)
    """
    is_valid, default_value = validate_template_numeric(value, "0,00 RON")
    if not is_valid:
        return default_value

    try:
        # Convert to Decimal for precise calculation
        decimal_value = Decimal(str(value))

        # Format with 2 decimal places
        formatted = f"{decimal_value:.2f}"

        # Split integer and decimal parts
        parts = formatted.split(".")
        integer_part = parts[0]
        decimal_part = parts[1]

        # Add thousand separators (dots in Romanian style)
        # Format: 1.234.567,89
        integer_with_separators = ""
        for i, digit in enumerate(reversed(integer_part)):
            if i > 0 and i % 3 == 0:
                integer_with_separators = "." + integer_with_separators
            integer_with_separators = digit + integer_with_separators

        # Use comma as decimal separator (Romanian style)
        romanian_formatted = f"{integer_with_separators},{decimal_part}"

        return f"{romanian_formatted} {currency}"

    except (ValueError, TypeError):
        return "0,00 RON"


@register.filter
def romanian_vat(value: TemplateNumeric, vat_rate: float = 0.21) -> str:
    """
    Calculate and format VAT amount in Romanian style

    Usage:
        {{ subtotal|romanian_vat }}        -> "105,00 RON TVA"
        {{ amount|romanian_vat:0.05 }}     -> "25,00 RON TVA"

    Args:
        value: Base amount for VAT calculation
        vat_rate: VAT rate (default 21% for Romania)
    """
    if value is None:
        return "0,00 RON TVA"

    try:
        decimal_value = Decimal(str(value))
        vat_amount = decimal_value * Decimal(str(vat_rate))
        formatted_vat = romanian_currency(vat_amount).replace(" RON", "")
        return f"{formatted_vat} RON TVA"
    except (ValueError, TypeError):
        return "0,00 RON TVA"


# Romanian date formatting constants
ROMANIAN_MONTH_SHORT = {
    1: "ian.",
    2: "feb.",
    3: "mar.",
    4: "apr.",
    5: "mai",
    6: "iun.",
    7: "iul.",
    8: "aug.",
    9: "sep.",
    10: "oct.",
    11: "nov.",
    12: "dec.",
}

ROMANIAN_MONTH_LONG = {
    1: "ianuarie",
    2: "februarie",
    3: "martie",
    4: "aprilie",
    5: "mai",
    6: "iunie",
    7: "iulie",
    8: "august",
    9: "septembrie",
    10: "octombrie",
    11: "noiembrie",
    12: "decembrie",
}


# Romanian date formatter registry
def _format_short_date(value: Any) -> str:
    """Format as: 15 ian. 2024"""
    return f"{value.day} {ROMANIAN_MONTH_SHORT[value.month]} {value.year}"


def _format_long_date(value: Any) -> str:
    """Format as: 15 ianuarie 2024"""
    return f"{value.day} {ROMANIAN_MONTH_LONG[value.month]} {value.year}"


def _format_datetime(value: Any) -> str:
    """Format as: 15 ian. 2024, 14:30"""
    return f"{value.day} {ROMANIAN_MONTH_SHORT[value.month]} {value.year}, {value.hour:02d}:{value.minute:02d}"


def _format_time_only(value: Any) -> str:
    """Format as: 14:30"""
    return f"{value.hour:02d}:{value.minute:02d}"


def _format_default(value: Any) -> str:
    """Default fallback formatting"""
    return str(value)


ROMANIAN_DATE_FORMATTERS = {
    "short": _format_short_date,
    "long": _format_long_date,
    "datetime": _format_datetime,
    "time": _format_time_only,
}


@register.filter
def romanian_date(value: Any, format_type: str = "short") -> str:
    """
    Format dates in Romanian business style using formatter registry

    Usage:
        {{ invoice.date|romanian_date }}           -> "15 ian. 2024"
        {{ deadline|romanian_date:"long" }}       -> "15 ianuarie 2024"
        {{ timestamp|romanian_date:"datetime" }}  -> "15 ian. 2024, 14:30"

    Args:
        value: Date/datetime object
        format_type: short|long|datetime|time
    """
    if not value:
        return ""

    try:
        formatter = ROMANIAN_DATE_FORMATTERS.get(format_type, _format_default)
        return formatter(value)
    except (AttributeError, KeyError):
        return str(value)


def _format_seconds_relative(seconds: float) -> str:
    """Format time in seconds range (under 1 minute)."""
    return "acum câteva secunde"


def _format_minutes_relative(seconds: float) -> str:
    """Format time in minutes range (1 minute to 1 hour)."""
    minutes = int(seconds // SECONDS_PER_MINUTE)
    if minutes == 1:
        return "acum un minut"
    elif minutes < ROMANIAN_TIME_MINUTE_PLURAL_THRESHOLD:
        return f"acum {minutes} minute"
    else:
        return f"acum {minutes} de minute"


def _format_hours_relative(seconds: float) -> str:
    """Format time in hours range (1 hour to 1 day)."""
    hours = int(seconds // SECONDS_PER_HOUR)
    if hours == 1:
        return "acum o oră"
    elif hours < ROMANIAN_TIME_HOUR_PLURAL_THRESHOLD:
        return f"acum {hours} ore"
    else:
        return f"acum {hours} de ore"


def _format_days_relative(seconds: float) -> str:
    """Format time in days range (1 day to 1 week)."""
    if seconds < SECONDS_PER_TWO_DAYS:  # 2 days
        return "ieri"
    else:
        days = int(seconds // SECONDS_PER_DAY)
        return f"acum {days} zile"


# Romanian relative date formatter registry
def _format_old_date(value: Any) -> str:
    """Format dates older than a week using short date format."""
    return romanian_date(value, "short")


ROMANIAN_RELATIVE_FORMATTERS = [
    (SECONDS_PER_MINUTE, _format_seconds_relative),
    (SECONDS_PER_HOUR, _format_minutes_relative),
    (SECONDS_PER_DAY, _format_hours_relative),
    (SECONDS_PER_WEEK, _format_days_relative),
    (float("inf"), _format_old_date),  # Fallback for very old dates
]


@register.filter
def romanian_relative_date(value: Any) -> str:
    """
    Format relative dates in Romanian using formatter registry

    Usage:
        {{ created_at|romanian_relative_date }}  -> "acum 2 ore"
        {{ last_login|romanian_relative_date }}  -> "ieri"
    """
    if not value:
        return ""

    try:
        now = timezone.now()
        diff = now - value
        seconds = diff.total_seconds()

        # Find the appropriate formatter based on time threshold
        for threshold, formatter in ROMANIAN_RELATIVE_FORMATTERS:
            if seconds < threshold:
                return formatter(seconds) if formatter != _format_old_date else formatter(value)

        # Fallback (should never reach here due to inf threshold)
        return str(value)

    except (AttributeError, TypeError):
        return str(value)


@register.filter
def cui_format(value: str) -> str:
    """
    Format Romanian CUI (Company Unique Identifier)

    Usage:
        {{ company.cui|cui_format }}  -> "RO 12345678"

    Args:
        value: CUI string (with or without RO prefix)
    """
    if not value:
        return ""

    # Remove whitespace and convert to uppercase
    cui = str(value).strip().upper()

    # Remove RO prefix if present
    if cui.startswith("RO"):
        cui = cui[2:].strip()

    # Validate CUI format (should be 2-10 digits)
    if not re.match(r"^\d{2,10}$", cui):
        return value  # Return original if invalid

    return f"RO {cui}"


@register.filter
def iban_format(value: str) -> str:
    """
    Format Romanian IBAN for display

    Usage:
        {{ account.iban|iban_format }}  -> "RO49 AAAA 1B31 0075 9384 0000"

    Args:
        value: IBAN string
    """
    if not value:
        return ""

    # Remove whitespace and convert to uppercase
    iban = str(value).strip().upper().replace(" ", "")

    # Validate Romanian IBAN (should start with RO and be 24 characters)
    if not iban.startswith("RO") or len(iban) != ROMANIAN_IBAN_LENGTH:
        return value  # Return original if invalid

    # Format in groups of 4 characters
    # ⚡ PERFORMANCE: Use list comprehension for better performance
    formatted_parts = [iban[i : i + 4] for i in range(0, len(iban), 4)]

    return " ".join(formatted_parts)


@register.filter
def phone_format(value: str, country_code: str = "+40") -> str:
    """
    Format Romanian phone numbers

    Usage:
        {{ contact.phone|phone_format }}      -> "+40 721 123 456"
        {{ mobile|phone_format:"+49" }}       -> "+49 721 123 456"

    Args:
        value: Phone number string
        country_code: Country code prefix
    """
    if not value:
        return ""

    # Remove all non-digit characters
    digits = re.sub(r"\D", "", str(value))

    # Handle Romanian numbers
    if country_code == "+40":
        if digits.startswith("40"):
            digits = digits[2:]  # Remove country code
        elif digits.startswith("0"):
            digits = digits[1:]  # Remove leading 0

        # Format based on length
        if len(digits) == PHONE_MOBILE_LENGTH:
            # Mobile: 721123456 -> +40 721 123 456
            return f"+40 {digits[:3]} {digits[3:6]} {digits[6:]}"
        elif len(digits) == PHONE_LANDLINE_LENGTH:
            # Landline: 0213123456 -> +40 21 312 34 56
            return f"+40 {digits[:2]} {digits[2:5]} {digits[5:7]} {digits[7:]}"

    # For other countries or invalid Romanian numbers, return formatted
    if len(digits) >= PHONE_MIN_VALID_LENGTH:
        return f"{country_code} {digits}"

    return value


@register.filter
def postal_code_format(value: str) -> str:
    """
    Format Romanian postal codes

    Usage:
        {{ address.postal_code|postal_code_format }}  -> "012345"

    Args:
        value: Postal code string
    """
    if not value:
        return ""

    # Remove whitespace and non-digits
    postal_code = re.sub(r"\D", "", str(value))

    # Romanian postal codes are 6 digits
    if len(postal_code) == ROMANIAN_POSTAL_CODE_LENGTH:
        return postal_code

    return value  # Return original if invalid


@register.filter
def contract_number_format(value: str) -> str:
    """
    Format contract numbers for Romanian business

    Usage:
        {{ contract.number|contract_number_format }}  -> "CRM-2024-001234"

    Args:
        value: Contract number string
    """
    if not value:
        return ""

    contract_num = str(value).strip().upper()

    # If it looks like a simple number, format it nicely
    if contract_num.isdigit():
        year = timezone.now().year
        return f"CRM-{year}-{contract_num.zfill(6)}"

    return contract_num


@register.simple_tag
def romanian_business_hours() -> str:
    """
    Display Romanian business hours

    Usage:
        {% romanian_business_hours %}  -> "Luni-Vineri: 09:00-18:00"
    """
    return "Luni-Vineri: 09:00-18:00"


@register.simple_tag
def romanian_legal_notice() -> str:
    """
    Standard Romanian legal notice for business documents

    Usage:
        {% romanian_legal_notice %}
    """
    return mark_safe(  # nosec B308 B703 - Static legal text, no user input
        "Această factură este emisă în conformitate cu Legea 227/2015 "
        "privind Codul fiscal și HG 1/2016 pentru aplicarea Codului fiscal."
    )


@register.filter
def romanian_plural(count: int, singular: str, plural: str, genitive: str | None = None) -> str:
    """
    Romanian plural forms based on count

    Usage:
        {{ client_count|romanian_plural:"client,clienți,de clienți" }}
        {{ server_count|romanian_plural:"server,servere,de servere" }}

    Args:
        count: Number to determine plural form
        singular: Singular form
        plural: Plural form (2-19)
        genitive: Genitive plural form (20+, optional)
    """
    if "," in plural:
        forms = plural.split(",")
        singular_form = forms[0] if len(forms) > 0 else singular
        plural_form = forms[1] if len(forms) > 1 else plural
        genitive_form = forms[2] if len(forms) > ROMANIAN_PLURAL_FEW_MIN else plural_form
    else:
        singular_form = singular
        plural_form = plural
        genitive_form = genitive or plural

    if count == ROMANIAN_PLURAL_SINGLE:
        return f"{count} {singular_form}"
    elif ROMANIAN_PLURAL_FEW_MIN <= count <= ROMANIAN_PLURAL_FEW_MAX:
        return f"{count} {plural_form}"
    else:
        return f"{count} {genitive_form}"


@register.filter
def romanian_boolean(value: bool, true_text: str = "Da", false_text: str = "Nu") -> str:
    """
    Convert boolean to Romanian text

    Usage:
        {{ is_active|romanian_boolean }}               -> "Da" / "Nu"
        {{ has_ssl|romanian_boolean:"Activ,Inactiv" }} -> "Activ" / "Inactiv"

    Args:
        value: Boolean value
        true_text: Text for True (default "Da")
        false_text: Text for False (default "Nu")
    """
    if "," in true_text:
        true_val, false_val = true_text.split(",", 1)
    else:
        true_val, false_val = true_text, false_text

    return true_val if value else false_val


@register.filter
def cents_to_currency(value: int | float | Decimal) -> Decimal:
    """
    Convert cents to currency units (divide by 100)

    Usage:
        {{ invoice.total_cents|cents_to_currency }}  -> 119.00 (from 11900)
        {{ amount_cents|cents_to_currency|romanian_currency }}

    Args:
        value: Amount in cents
    """
    if value is None or value == "":
        return Decimal("0.00")

    try:
        # Handle various input types
        if hasattr(value, "__str__"):
            str_value = str(value).strip()
            if str_value == "" or str_value.lower() == "none":
                return Decimal("0.00")
            return Decimal(str_value) / Decimal("100")
        else:
            return Decimal(str(value)) / Decimal("100")
    except (ValueError, TypeError, decimal.InvalidOperation):
        return Decimal("0.00")


@register.filter
def multiply(value: TemplateNumeric, multiplier: TemplateNumeric) -> Decimal:
    """
    Multiply two numbers safely with decimal precision

    Usage:
        {{ price|multiply:1.19 }}           -> 118.99 (from 100)
        {{ subtotal|multiply:vat_rate }}    -> 105.00 (from 500 with 0.21)
        {{ amount|multiply:quantity }}      -> 300.00 (from 100 and 3)

    Args:
        value: Base number to multiply
        multiplier: Number to multiply by
    """
    if value is None or multiplier is None:
        return Decimal("0.00")

    try:
        base = Decimal(str(value))
        mult = Decimal(str(multiplier))
        return base * mult
    except (ValueError, TypeError):
        return Decimal("0.00")


@register.filter
def divide(value: TemplateNumeric, divisor: TemplateNumeric) -> Decimal:
    """
    Divide two numbers safely with decimal precision

    Usage:
        {{ total|divide:1.19 }}           -> 84.03 (from 100)
        {{ vat_amount|divide:0.21 }}      -> 500.00 (from 105)

    Args:
        value: Base number to divide
        divisor: Number to divide by
    """
    if value is None or divisor is None:
        return Decimal("0.00")

    try:
        base = Decimal(str(value))
        div = Decimal(str(divisor))
        if div == 0:
            return Decimal("0.00")
        return base / div
    except (ValueError, TypeError, ZeroDivisionError):
        return Decimal("0.00")


@register.filter
def highlight_search(text: str, search_term: str) -> SafeString:
    """
    Highlight search terms in Romanian text (case-insensitive, diacritic-aware)

    🔒 SECURITY: HTML-escapes input before highlighting to prevent XSS

    Usage:
        {{ description|highlight_search:query }}

    Args:
        text: Text to search in
        search_term: Term to highlight
    """
    if not text or not search_term:
        return mark_safe(escape(text) if text else "")  # noqa: S308

    # First escape HTML to prevent XSS
    escaped_text = escape(text)
    escaped_search = escape(search_term)

    # Romanian diacritic mapping for search
    diacritic_map = {"ă": "a", "â": "a", "î": "i", "ș": "s", "ț": "t", "Ă": "A", "Â": "A", "Î": "I", "Ș": "S", "Ț": "T"}

    def normalize_text(s: str) -> str:
        """Remove diacritics for search comparison"""
        for diacritic, replacement in diacritic_map.items():
            s = s.replace(diacritic, replacement)
        return s.lower()

    normalized_text = normalize_text(escaped_text)
    normalized_search = normalize_text(escaped_search)

    # Find matches
    highlighted: str = escaped_text
    start = 0
    while True:
        pos = normalized_text.find(normalized_search, start)
        if pos == -1:
            break

        # Get the original text portion to preserve diacritics
        original_match = escaped_text[pos : pos + len(escaped_search)]
        highlighted_match = f'<mark class="bg-yellow-200">{original_match}</mark>'

        # Replace in the highlighted text
        highlighted = highlighted[:pos] + highlighted_match + highlighted[pos + len(escaped_search) :]

        start = pos + len(highlighted_match)
        # Update the normalized text for next search
        normalized_text = normalize_text(highlighted)

    return mark_safe(highlighted)  # nosec B308 B703 - Input is HTML-escaped before highlighting  # noqa: S308
