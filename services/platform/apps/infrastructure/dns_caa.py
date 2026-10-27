"""CAA issue-value syntax from RFC 8659 section 4.2; issuer parameters stay unverified."""

from __future__ import annotations

import re

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_ISSUER = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
_PARAMETER = re.compile(rf"{_LABEL}[ \t]*=[ \t]*[\x21-\x3a\x3c-\x7e]*")


def parse_caa_issue(value: bytes) -> tuple[str, bool] | None:
    """Return the issuer and whether parameters exist; malformed values authorize no issuer."""
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        return None
    issuer, separator, parameters = text.partition(";")
    issuer = issuer.strip(" \t")
    if issuer and _ISSUER.fullmatch(issuer) is None:
        return None
    if not separator or not parameters.strip(" \t"):
        return issuer.lower(), False
    if any(_PARAMETER.fullmatch(item.strip(" \t")) is None for item in parameters.split(";")):
        return None
    return issuer.lower(), True
