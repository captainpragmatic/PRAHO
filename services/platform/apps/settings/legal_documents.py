"""Staff publish the operator's legal documents (ADR-0058).

A release is never edited or removed: a correction is another release, taking effect on its date.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from django import forms
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.translation import gettext
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods

from apps.common.decorators import admin_required
from apps.common.legal import LegalDocument, publish_legal_document, render_legal_markdown
from apps.common.localisation import LANGUAGE_CHOICES
from apps.common.request_ip import get_safe_client_ip
from apps.common.utils import operator_local_date

from .views import _sidebar_context

if TYPE_CHECKING:
    from apps.users.models import User


class LegalDocumentForm(forms.Form):
    kind = forms.ChoiceField(label=_("Document"), choices=LegalDocument.Kind.choices)
    language = forms.ChoiceField(label=_("Language"), choices=LANGUAGE_CHOICES)
    effective_on = forms.DateField(
        label=_("In effect from"), widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d")
    )
    body_markdown = forms.CharField(
        label=_("Text"),
        help_text=_("Markdown: headings, lists, links, emphasis, quotes and tables."),
        widget=forms.Textarea(attrs={"rows": 20}),
    )


def _in_force_ids() -> set[Any]:
    """The release in force for each document and language: the first of its kind and language."""
    in_force: dict[tuple[str, str], Any] = {}
    for pk, kind, language in LegalDocument.objects.in_force(operator_local_date(timezone.now())).values_list(
        "pk", "kind", "language"
    ):
        in_force.setdefault((kind, language), pk)
    return set(in_force.values())


@admin_required
@require_http_methods(["GET", "POST"])
def legal_documents(request: HttpRequest) -> HttpResponse:
    """The releases published so far, and a form to preview and publish another."""
    form = LegalDocumentForm(request.POST or None, initial={"effective_on": operator_local_date(timezone.now())})
    preview = ""
    if request.method == "POST" and form.is_valid():
        if request.POST.get("action") == "publish":
            result = publish_legal_document(
                **form.cleaned_data, published_by=cast("User", request.user), ip_address=get_safe_client_ip(request)
            )
            if result.is_ok():
                messages.success(request, gettext("Published %(release)s.") % {"release": result.unwrap()})
                return redirect("settings:legal_documents")
            form.add_error(None, result.unwrap_err())
        else:
            preview = render_legal_markdown(form.cleaned_data["body_markdown"])

    documents = (
        LegalDocument.objects.select_related("published_by")
        .defer("body_markdown", "body_html")
        .order_by("kind", "language", "-effective_on", "-created_at")
    )
    context = {
        **_sidebar_context(None, request.user),
        "is_admin": True,
        "form": form,
        "preview": preview,
        "documents": documents,
        "in_force": _in_force_ids(),
    }
    return render(request, "settings/legal_documents.html", context)
