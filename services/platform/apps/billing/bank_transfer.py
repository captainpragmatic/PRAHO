"""Bank instructions are selected using the payable record's currency."""

import re

from django.conf import settings

from apps.settings.services import SettingsService

from .currency_service import normalize_currency_code


def bank_transfer_instructions(
    currency_code: str, *, ron_fallback: dict[str, str] | None = None
) -> dict[str, str] | None:
    try:
        code = normalize_currency_code(currency_code)
    except ValueError:
        return None
    accounts = SettingsService.get_setting("billing.bank_accounts", {})
    if not isinstance(accounts, dict):
        return None
    account = accounts.get(code)
    if code == "RON" and code not in accounts:
        account = (
            ron_fallback
            if ron_fallback is not None
            else {
                "iban": getattr(settings, "COMPANY_BANK_ACCOUNT", ""),
                "bank_name": getattr(settings, "COMPANY_BANK_NAME", ""),
                "beneficiary": getattr(settings, "COMPANY_NAME", ""),
            }
        )
    if not isinstance(account, dict):
        return None
    required = ("iban", "bank_name", "beneficiary")
    if any(not isinstance(account.get(field), str) or not account[field].strip() for field in required):
        return None
    iban = re.sub(r"\s+", "", account["iban"]).upper()
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}", iban):
        return None
    result = {field: account[field].strip() for field in required}
    result.update(iban=iban, currency=code)
    if isinstance(account.get("swift"), str) and account["swift"].strip():
        result["swift"] = account["swift"].strip()
    return result
