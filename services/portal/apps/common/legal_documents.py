"""The operator's published legal documents, read from Platform and shown as published (ADR-0062).

The release in force for a kind and language is cached for a minute; while Platform cannot answer,
the last answer read stands in for up to an hour. A release read by its id never changes, so it is
kept for a day. Platform's HTML must match the hash published with it, and is sanitised again here
before it is cached, so nothing outside the legal allowlist is ever shown.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import date
from http import HTTPStatus
from typing import TypedDict

from django.core.cache import cache
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.legal_html import sanitize_legal_html
from apps.common.localisation_services import platform_cache_key

logger = logging.getLogger(__name__)

TITLES = {
    "terms": gettext_lazy("Terms of Service"),
    "privacy": gettext_lazy("Privacy Policy"),
    "cookies": gettext_lazy("Cookie Policy"),
}
_FIELDS = frozenset({"id", "kind", "language", "release", "effective_on", "html", "sha256"})
_NOT_PUBLISHED = "not_published"  # Cached like a document: Platform's answer when there is none
_CURRENT_SECONDS = 60
_LAST_GOOD_SECONDS = 60 * 60
_RELEASE_SECONDS = 24 * 60 * 60


class LegalDocumentsUnavailableError(Exception):
    """Platform could not be asked, and no earlier answer can stand in."""


class LegalDocument(TypedDict):
    id: str
    kind: str
    language: str
    release: str
    effective_on: date
    html: SafeString


def _fetch(request: dict[str, str]) -> LegalDocument | str:
    """Platform's answer for this request: the document, ready to show, or _NOT_PUBLISHED."""
    try:
        response = api_client.get_legal_document(request)
    except PlatformAPIError as exc:
        if exc.status_code == HTTPStatus.NOT_FOUND and (exc.response_data or {}).get("code") == _NOT_PUBLISHED:
            return _NOT_PUBLISHED
        raise LegalDocumentsUnavailableError from exc
    answer = response.get("document") if response.get("success") is True else None
    try:
        if (
            not isinstance(answer, dict)
            or set(answer) != _FIELDS
            or not all(isinstance(value, str) for value in answer.values())
            or answer["kind"] not in TITLES
            # Asked by id, the id comes back; asked by kind, that kind. The language may be the default one.
            or any(answer[field] != value for field, value in request.items() if field != "language")
            or hashlib.sha256(answer["html"].encode()).hexdigest() != answer["sha256"]
        ):
            raise ValueError("unexpected fields or values")
        uuid.UUID(answer["id"])
        effective_on = date.fromisoformat(answer["effective_on"])
    except ValueError as exc:
        logger.warning("⚠️ [Legal] Platform's legal document answer was rejected: %s", exc)
        raise LegalDocumentsUnavailableError from exc
    return {
        "id": answer["id"],
        "kind": answer["kind"],
        "language": answer["language"],
        "release": answer["release"],
        "effective_on": effective_on,
        "html": sanitize_legal_html(answer["html"]),
    }


def _document(answer: LegalDocument | str) -> LegalDocument | None:
    return answer if isinstance(answer, dict) else None


def current_legal_document(kind: str, language: str) -> LegalDocument | None:
    """The release in force in this language, or the default language's; None if there is none.

    Raises LegalDocumentsUnavailableError when Platform cannot answer and nothing was read before.
    """
    key = f"{platform_cache_key('legal')}:current:{kind}:{language}"
    answer = cache.get(key)
    if answer is None:
        try:
            answer = _fetch({"kind": kind, "language": language})
        except LegalDocumentsUnavailableError:
            answer = cache.get(f"{key}:last_good")
            if answer is None:
                raise
        else:
            cache.set(f"{key}:last_good", answer, _LAST_GOOD_SECONDS)
        cache.set(key, answer, _CURRENT_SECONDS)  # An outage never extends the last good answer
    return _document(answer)


def legal_document_release(document_id: str) -> LegalDocument | None:
    """One release, as an acceptance names it; None if there is no such release."""
    key = f"{platform_cache_key('legal')}:release:{document_id}"
    answer = cache.get(key)
    if answer is None:
        answer = _fetch({"id": document_id})
        cache.set(key, answer, _RELEASE_SECONDS if isinstance(answer, dict) else _CURRENT_SECONDS)
    return _document(answer)
