"""Pure domain-name helpers shared by models and services."""

from __future__ import annotations

from collections.abc import Iterable

_MIN_DOMAIN_LABELS = 2


def canonicalize_domain_name(name: str) -> str:
    """THE canonical stored/compared form of a domain name (#442): stripped lowercase.

    DNS names are case-insensitive but ``Domain.name`` is an exact-match unique
    column, so every writer (``Domain.save``, the bulk-path queryset) and every
    exact-match reader (renew-link, webhooks, sync commands) must fold through this
    one function — a writer that strips while a reader doesn't is how mixed
    conventions silently miss rows.
    """
    return name.strip().lower()


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
