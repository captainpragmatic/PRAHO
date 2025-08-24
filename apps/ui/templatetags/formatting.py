"""
PRAHO PLATFORM - Romanian Formatting Template Tags
===============================================================================
Romanian business formatting for dates, currency, legal compliance
"""

from django import template
from django.utils import timezone
from django.utils.formats import date_format
from django.utils.safestring import mark_safe
from decimal import Decimal
from typing import Optional, Union
import re

register = template.Library()


@register.filter
def romanian_currency(value: Union[int, float, Decimal], currency: str = 'RON') -> str:
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
    if value is None:
        return "0,00 RON"
    
    try:
        # Convert to Decimal for precise calculation
        decimal_value = Decimal(str(value))
        
        # Format with 2 decimal places
        formatted = f"{decimal_value:.2f}"
        
        # Split integer and decimal parts
        parts = formatted.split('.')
        integer_part = parts[0]
        decimal_part = parts[1]
        
        # Add thousand separators (dots in Romanian style)
        # Format: 1.234.567,89
        integer_with_separators = ''
        for i, digit in enumerate(reversed(integer_part)):
            if i > 0 and i % 3 == 0:
                integer_with_separators = '.' + integer_with_separators
            integer_with_separators = digit + integer_with_separators
        
        # Use comma as decimal separator (Romanian style)
        romanian_formatted = f"{integer_with_separators},{decimal_part}"
        
        return f"{romanian_formatted} {currency}"
        
    except (ValueError, TypeError):
        return "0,00 RON"


@register.filter
def romanian_vat(value: Union[int, float, Decimal], vat_rate: float = 0.19) -> str:
    """
    Calculate and format VAT amount in Romanian style
    
    Usage:
        {{ subtotal|romanian_vat }}        -> "95,22 RON TVA"
        {{ amount|romanian_vat:0.05 }}     -> "25,00 RON TVA"
    
    Args:
        value: Base amount for VAT calculation
        vat_rate: VAT rate (default 19% for Romania)
    """
    if value is None:
        return "0,00 RON TVA"
    
    try:
        decimal_value = Decimal(str(value))
        vat_amount = decimal_value * Decimal(str(vat_rate))
        formatted_vat = romanian_currency(vat_amount).replace(' RON', '')
        return f"{formatted_vat} RON TVA"
    except (ValueError, TypeError):
        return "0,00 RON TVA"


@register.filter
def romanian_date(value, format_type: str = 'short') -> str:
    """
    Format dates in Romanian business style
    
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
    
    # Romanian month abbreviations
    month_short = {
        1: 'ian.', 2: 'feb.', 3: 'mar.', 4: 'apr.',
        5: 'mai', 6: 'iun.', 7: 'iul.', 8: 'aug.',
        9: 'sep.', 10: 'oct.', 11: 'nov.', 12: 'dec.'
    }
    
    # Romanian month full names
    month_long = {
        1: 'ianuarie', 2: 'februarie', 3: 'martie', 4: 'aprilie',
        5: 'mai', 6: 'iunie', 7: 'iulie', 8: 'august',
        9: 'septembrie', 10: 'octombrie', 11: 'noiembrie', 12: 'decembrie'
    }
    
    try:
        if format_type == 'short':
            # 15 ian. 2024
            return f"{value.day} {month_short[value.month]} {value.year}"
        elif format_type == 'long':
            # 15 ianuarie 2024
            return f"{value.day} {month_long[value.month]} {value.year}"
        elif format_type == 'datetime':
            # 15 ian. 2024, 14:30
            return f"{value.day} {month_short[value.month]} {value.year}, {value.hour:02d}:{value.minute:02d}"
        elif format_type == 'time':
            # 14:30
            return f"{value.hour:02d}:{value.minute:02d}"
        else:
            return str(value)
    except (AttributeError, KeyError):
        return str(value)


@register.filter
def romanian_relative_date(value) -> str:
    """
    Format relative dates in Romanian
    
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
        
        if seconds < 60:
            return "acum câteva secunde"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            if minutes == 1:
                return "acum un minut"
            elif minutes < 20:
                return f"acum {minutes} minute"
            else:
                return f"acum {minutes} de minute"
        elif seconds < 86400:
            hours = int(seconds // 3600)
            if hours == 1:
                return "acum o oră"
            elif hours < 20:
                return f"acum {hours} ore"
            else:
                return f"acum {hours} de ore"
        elif seconds < 172800:  # 2 days
            return "ieri"
        elif seconds < 604800:  # 7 days
            days = int(seconds // 86400)
            return f"acum {days} zile"
        else:
            # Use short date format for older dates
            return romanian_date(value, 'short')
            
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
    if cui.startswith('RO'):
        cui = cui[2:].strip()
    
    # Validate CUI format (should be 2-10 digits)
    if not re.match(r'^\d{2,10}$', cui):
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
    iban = str(value).strip().upper().replace(' ', '')
    
    # Validate Romanian IBAN (should start with RO and be 24 characters)
    if not iban.startswith('RO') or len(iban) != 24:
        return value  # Return original if invalid
    
    # Format in groups of 4 characters
    formatted_parts = []
    for i in range(0, len(iban), 4):
        formatted_parts.append(iban[i:i+4])
    
    return ' '.join(formatted_parts)


@register.filter
def phone_format(value: str, country_code: str = '+40') -> str:
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
    digits = re.sub(r'\D', '', str(value))
    
    # Handle Romanian numbers
    if country_code == '+40':
        if digits.startswith('40'):
            digits = digits[2:]  # Remove country code
        elif digits.startswith('0'):
            digits = digits[1:]  # Remove leading 0
        
        # Format based on length
        if len(digits) == 9:
            # Mobile: 721123456 -> +40 721 123 456
            return f"+40 {digits[:3]} {digits[3:6]} {digits[6:]}"
        elif len(digits) == 10:
            # Landline: 0213123456 -> +40 21 312 34 56
            return f"+40 {digits[:2]} {digits[2:5]} {digits[5:7]} {digits[7:]}"
    
    # For other countries or invalid Romanian numbers, return formatted
    if len(digits) >= 7:
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
    postal_code = re.sub(r'\D', '', str(value))
    
    # Romanian postal codes are 6 digits
    if len(postal_code) == 6:
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
def romanian_plural(count: int, singular: str, plural: str, genitive: Optional[str] = None) -> str:
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
    if ',' in plural:
        forms = plural.split(',')
        singular_form = forms[0] if len(forms) > 0 else singular
        plural_form = forms[1] if len(forms) > 1 else plural
        genitive_form = forms[2] if len(forms) > 2 else plural_form
    else:
        singular_form = singular
        plural_form = plural
        genitive_form = genitive or plural
    
    if count == 1:
        return f"{count} {singular_form}"
    elif 2 <= count <= 19:
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
    if ',' in true_text:
        true_val, false_val = true_text.split(',', 1)
    else:
        true_val, false_val = true_text, false_text
    
    return true_val if value else false_val


@register.filter
def cents_to_currency(value: Union[int, float, Decimal]) -> Decimal:
    """
    Convert cents to currency units (divide by 100)
    
    Usage:
        {{ invoice.total_cents|cents_to_currency }}  -> 119.00 (from 11900)
        {{ amount_cents|cents_to_currency|romanian_currency }}
    
    Args:
        value: Amount in cents
    """
    if value is None:
        return Decimal('0.00')
    
    try:
        return Decimal(str(value)) / Decimal('100')
    except (ValueError, TypeError):
        return Decimal('0.00')


@register.filter
def highlight_search(text: str, search_term: str) -> str:
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
        return text
    
    # First escape HTML to prevent XSS
    from django.utils.html import escape
    escaped_text = escape(text)
    escaped_search = escape(search_term)
    
    # Romanian diacritic mapping for search
    diacritic_map = {
        'ă': 'a', 'â': 'a', 'î': 'i', 'ș': 's', 'ț': 't',
        'Ă': 'A', 'Â': 'A', 'Î': 'I', 'Ș': 'S', 'Ț': 'T'
    }
    
    def normalize_text(s):
        """Remove diacritics for search comparison"""
        for diacritic, replacement in diacritic_map.items():
            s = s.replace(diacritic, replacement)
        return s.lower()
    
    normalized_text = normalize_text(escaped_text)
    normalized_search = normalize_text(escaped_search)
    
    # Find matches
    highlighted = escaped_text
    start = 0
    while True:
        pos = normalized_text.find(normalized_search, start)
        if pos == -1:
            break
        
        # Get the original text portion to preserve diacritics
        original_match = escaped_text[pos:pos + len(escaped_search)]
        highlighted_match = f'<mark class="bg-yellow-200">{original_match}</mark>'
        
        # Replace in the highlighted text
        highlighted = (
            highlighted[:pos] + 
            highlighted_match + 
            highlighted[pos + len(escaped_search):]
        )
        
        start = pos + len(highlighted_match)
        # Update the normalized text for next search
        normalized_text = normalize_text(highlighted)
    
    return mark_safe(highlighted)  # nosec B308 B703 - Input is HTML-escaped before highlighting
