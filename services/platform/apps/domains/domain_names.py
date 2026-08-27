"""Pure domain-name helpers shared by models and services."""

from __future__ import annotations

from collections.abc import Iterable

import idna

_MIN_DOMAIN_LABELS = 2


def canonicalize_domain_name(name: str) -> str:
    """THE canonical stored/compared form of a domain name (#442, #473).

    Stripped, lowercased, and — for internationalized names — folded through IDNA
    UTS-46 to the ASCII A-label, so a Unicode U-label and its punycode form can
    never become two distinct rows. ``Domain.name`` is an exact-match unique
    column: every writer (``Domain.save``, the bulk-path queryset) and every
    exact-match reader (renew-link, webhooks, sync commands) must fold through
    this one function.

    Never raises: it runs inside ``Domain.save()`` and the bulk write paths, so
    Unicode that UTS-46 rejects falls back to the stripped, lowercased form —
    the pre-#473 behavior for inputs that bypass service-boundary validation.
    """
    folded = name.strip().lower()
    if folded.isascii():
        return folded

    try:
        return idna.encode(folded, uts46=True).decode("ascii")
    except UnicodeError:
        return folded


def longest_matching_tld_suffix(domain_name: str, configured_extensions: Iterable[str]) -> str:
    """Return the longest configured suffix matching ``domain_name``.

    TLD configuration may contain multi-label public suffixes such as ``com.ro``.
    Candidate suffixes are therefore checked from most to least specific instead
    of assuming that the final DNS label identifies the configured product.
    """
    labels = domain_name.strip().lower().split(".")
    if len(labels) < _MIN_DOMAIN_LABELS or any(not label for label in labels):
        return ""

    extensions = {extension.strip().lower() for extension in configured_extensions}
    extensions.discard("")

    for label_index in range(1, len(labels)):
        candidate = ".".join(labels[label_index:])
        if candidate in extensions:
            return candidate
    return ""
