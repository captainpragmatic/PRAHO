"""Legal documents the operator publishes: Terms of Service, Privacy Policy and Cookie Policy (ADR-0061).

PRAHO ships no legal text. Staff publish each document as a release that takes effect on a date and
is never edited or removed afterwards; a correction is another release. The portal shows the release
in force, and an acceptance records exactly which release it was (`LegalDocument.reference()`).
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable
from datetime import date
from typing import TYPE_CHECKING, Any, NoReturn, TypedDict

import markdown
from django.conf import settings
from django.db import IntegrityError, models, transaction
from django.utils import timezone
from django.utils.html import escape
from django.utils.safestring import SafeString
from django.utils.translation import gettext
from django.utils.translation import gettext_lazy as _

from apps.common.legal_html import sanitize_legal_html
from apps.common.localisation import LANGUAGES
from apps.common.types import Err, Ok, Result
from apps.common.utils import operator_local_date

if TYPE_CHECKING:
    from apps.users.models import User


class LegalDocumentImmutableError(Exception):
    """A published legal document was about to change. Releases are never edited or removed."""


class LegalDocumentReference(TypedDict):
    """The exact text someone was shown or accepted."""

    document_id: str
    kind: str
    language: str
    release: str
    sha256: str


def _refuse(operation: str) -> NoReturn:
    raise LegalDocumentImmutableError(f"A published legal document cannot change: {operation} refused")


# Why nobody can register while no Terms of Service are in force.
TERMS_UNAVAILABLE = _("Registration opens once the Terms of Service are published.")


class LegalDocumentQuerySet(models.QuerySet["LegalDocument"]):
    """Rows are only ever inserted, one at a time, by publish_legal_document()."""

    def in_force(self, today: date) -> LegalDocumentQuerySet:
        """Releases already in effect, the one in force first: latest effective date, then latest published."""
        return self.filter(effective_on__lte=today).order_by("-effective_on", "-created_at")

    def update(self, **kwargs: Any) -> int:
        _refuse("update()")

    def bulk_update(self, objs: Iterable[LegalDocument], fields: Iterable[str], batch_size: int | None = None) -> int:
        _refuse("bulk_update()")

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[LegalDocument]:
        _refuse("bulk_create()")

    def delete(self) -> tuple[int, dict[str, int]]:
        _refuse("delete()")


class LegalDocument(models.Model):
    class Kind(models.TextChoices):
        TERMS = "terms", _("Terms of Service")
        PRIVACY = "privacy", _("Privacy Policy")
        COOKIES = "cookies", _("Cookie Policy")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=20, choices=Kind.choices)
    language = models.CharField(max_length=10)
    # "<effective date>.<n>": the n-th release taking effect that day, e.g. 2026-11-01.1
    release = models.CharField(max_length=20)
    effective_on = models.DateField()
    body_markdown = models.TextField()
    body_html = models.TextField()  # Rendered and sanitised when published
    sha256 = models.CharField(max_length=64)  # Of body_html, the text customers see
    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    # No updated_at: a release is never updated.
    created_at = models.DateTimeField(auto_now_add=True)

    objects = LegalDocumentQuerySet.as_manager()

    class Meta:
        db_table = "common_legal_documents"
        constraints = (
            models.UniqueConstraint(fields=("kind", "language", "release"), name="legal_document_release_unique"),
        )
        indexes = (
            models.Index(fields=("kind", "language", "-effective_on", "-created_at"), name="legal_doc_in_force"),
        )

    def __str__(self) -> str:
        return f"{self.get_kind_display()} {self.language} {self.release}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding or kwargs.get("force_update") or kwargs.get("update_fields") is not None:
            _refuse("save() of a stored release")
        kwargs["force_insert"] = True  # An instance carrying a stored release's id fails, never overwrites
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> NoReturn:
        _refuse("delete()")

    def attachment(self) -> tuple[str, bytes, str]:
        """The release as a standalone HTML file: what an email attaches as the durable copy."""
        title = escape(f"{self.get_kind_display()} {self.release}")
        page = (
            f'<!doctype html><html lang="{escape(self.language)}"><head><meta charset="utf-8"><title>{title}</title>'
            f"</head><body><h1>{title}</h1><p>{escape(self.effective_on.isoformat())}</p>{self.body_html}</body></html>"
        )
        return f"{self.kind}-{self.release}.html", page.encode(), "text/html"

    def reference(self) -> LegalDocumentReference:
        return {
            "document_id": str(self.pk),
            "kind": self.kind,
            "language": self.language,
            "release": self.release,
            "sha256": self.sha256,
        }


def render_legal_markdown(body_markdown: str) -> SafeString:
    """The HTML a release shows: Markdown rendered, then sanitised to the legal allowlist."""
    return sanitize_legal_html(markdown.markdown(body_markdown, extensions=["tables", "sane_lists"]))


def current_legal_document(kind: str, language: str) -> LegalDocument | None:
    """The release in force today in this language, else in the default language, or None if none is."""
    from apps.settings.services import SettingsService  # noqa: PLC0415  # ADR-0007: cross-app service at call time

    in_force = (
        LegalDocument.objects.in_force(operator_local_date(timezone.now())).filter(kind=kind).defer("body_markdown")
    )
    document = in_force.filter(language=language).first()
    if document is None:
        default_language = SettingsService.get_setting("system.default_language")
        if default_language != language:
            document = in_force.filter(language=default_language).first()
    return document


def any_legal_document_in_force(kind: str) -> bool:
    """Whether a release of this document is in force today, in any language."""
    return LegalDocument.objects.in_force(operator_local_date(timezone.now())).filter(kind=kind).exists()


def legal_document_in_force(document_id: uuid.UUID, kind: str) -> LegalDocument | None:
    """The release with this id if it is the one in force for its own language, else None."""
    document = LegalDocument.objects.filter(pk=document_id, kind=kind).first()
    if document is None or current_legal_document(kind, document.language) != document:
        return None
    return document


def publish_legal_document(  # noqa: PLR0913  # One argument per fact a release records
    *,
    kind: str,
    language: str,
    effective_on: date,
    body_markdown: str,
    published_by: User | None,
    ip_address: str | None = None,
) -> Result[LegalDocument, str]:
    """Publish a release, audited in the same transaction. It takes effect on its date, never earlier."""
    from apps.audit.services import AuditService  # noqa: PLC0415  # ADR-0007: cross-app service at call time

    if kind not in LegalDocument.Kind.values:
        return Err(gettext("Choose which document this is."))
    if language not in LANGUAGES:
        return Err(gettext("Choose a supported language."))
    if effective_on < operator_local_date(timezone.now()):
        return Err(gettext("A release cannot take effect in the past."))
    if not body_markdown.strip():
        return Err(gettext("The document has no text."))

    body_html = render_legal_markdown(body_markdown)
    prefix = f"{effective_on.isoformat()}."
    try:
        with transaction.atomic():
            # Releases are never deleted, so the count only grows; a concurrent publish of the same
            # number fails the unique constraint and rolls back with its audit event.
            number = LegalDocument.objects.filter(kind=kind, language=language, release__startswith=prefix).count()
            document = LegalDocument.objects.create(
                kind=kind,
                language=language,
                release=f"{prefix}{number + 1}",
                effective_on=effective_on,
                body_markdown=body_markdown,
                body_html=body_html,
                sha256=hashlib.sha256(body_html.encode()).hexdigest(),
                published_by=published_by,
            )
            AuditService.log_simple_event(
                "legal_document_published",
                user=published_by,
                content_object=document,
                description=f"Published {document}",
                metadata={"reference": document.reference(), "effective_on": effective_on.isoformat()},
                ip_address=ip_address,
            )
    except IntegrityError:
        return Err(gettext("Another release of this document was published at the same moment. Publish again."))
    return Ok(document)
