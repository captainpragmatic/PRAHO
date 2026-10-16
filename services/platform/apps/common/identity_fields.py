"""Phone and VAT number rules that follow the customer's country. Identical in both services.

A phone number is stored in international form (+<country code><number>); a Romanian customer may
also type the national form, which becomes +40. An EU VAT number is stored with its country prefix,
Greece's being EL as VIES expects, and a number typed without one belongs to the customer's
country. A tax ID from outside the EU is kept as entered: PRAHO has no rule for it.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from stdnum.eu import vat as eu_vat
from stdnum.ro import cui as ro_cui

from apps.common.localisation import normalize_country_code

MAX_PHONE_LENGTH = 32
MAX_VAT_NUMBER_LENGTH = 20
_INTERNATIONAL_PHONE = re.compile(r"\+[1-9][0-9]{6,14}")  # E.164
_ROMANIAN_INTERNATIONAL_PHONE = re.compile(r"\+40[0-9]{9}")
_ROMANIAN_NATIONAL_PHONE = re.compile(r"0[0-9]{9}")
_PHONE_SEPARATORS = re.compile(r"[\s.\-()/]")
_VAT_SEPARATORS = re.compile(r"[\s.\-]")
# The VAT prefixes VIES knows: Greece's is EL, so a GR-prefixed value is another identifier.
_VAT_PREFIXES = frozenset({state.upper() for state in eu_vat.MEMBER_STATES} - {"GR"} | {"EL"})


def requires_county(country: object) -> bool:
    """Only a Romanian address needs its county: e-Factura (CIUS-RO) requires it."""
    return normalize_country_code(country) == "RO"


def validate_international_phone(value: str) -> None:
    """A stored phone number is in international form; a Romanian one has nine digits after +40."""
    pattern = _ROMANIAN_INTERNATIONAL_PHONE if value.startswith("+40") else _INTERNATIONAL_PHONE
    if value and not pattern.fullmatch(value):
        raise ValidationError(_("Enter the phone number with its country code, for example +40 721 123 456."))


def normalize_phone(value: object, country: object = "") -> str:
    """The number in international form; blank stays blank."""
    raw = str(value or "").strip()
    if len(raw) > MAX_PHONE_LENGTH:
        raise ValidationError(_("Enter the phone number with its country code, for example +40 721 123 456."))
    number = _PHONE_SEPARATORS.sub("", raw)
    if number.startswith("00"):
        number = "+" + number[2:]
    elif normalize_country_code(country) == "RO" and _ROMANIAN_NATIONAL_PHONE.fullmatch(number):
        number = "+40" + number[1:]
    validate_international_phone(number)
    return number


def normalize_vat_number(value: object, country: object = "") -> str:
    """An EU VAT number with its country prefix, checked; any other tax ID as entered; blank stays blank."""
    entered = str(value or "").strip()
    if len(entered) > MAX_VAT_NUMBER_LENGTH:
        raise ValidationError(_("The VAT number is too long."))
    number = _VAT_SEPARATORS.sub("", entered).upper()
    if not number:
        return ""
    if not number[:2].isalpha():
        customer_country = normalize_country_code(country)
        number = ("EL" if customer_country == "GR" else customer_country) + number
    if number[:2] not in _VAT_PREFIXES:
        return entered
    # A Romanian VAT number is a CUI: the VAT check alone would also accept a CNP.
    valid = ro_cui.is_valid(number[2:]) if number.startswith("RO") else eu_vat.is_valid(number)
    if not valid:
        raise ValidationError(_("Enter a valid EU VAT number, with or without its country prefix."))
    return str(eu_vat.compact(number))


def clean_with_country(
    form: forms.BaseForm, name: str, normalize: Callable[[object, object], str], country: object
) -> None:
    """In a form's clean(): normalize one field by its country's rules, reporting a refusal on that field.

    A field that already failed its own validation is not in cleaned_data, and is left alone.
    """
    if name not in form.cleaned_data:
        return
    try:
        form.cleaned_data[name] = normalize(form.cleaned_data[name], country)
    except ValidationError as error:
        form.add_error(name, error)
