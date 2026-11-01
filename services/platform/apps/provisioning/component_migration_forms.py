"""Explicit bounded component selection and operator impact acceptance."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, cast

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from apps.ui.widgets import PRAHOCheckboxWidget, PRAHOSelectWidget

from .component_migration_manifest import MAX_COMPONENTS, MAX_PATH_LENGTH
from .virtualmin_models import VirtualminServer
from .virtualmin_node_capability import destination_refusal

if TYPE_CHECKING:
    from .virtualmin_models import VirtualminAccount

RESERVED_ROOTS = frozenset({"mail", "maildir", "homes", "domains", "logs", "etc", "tmp", "cgi-bin"})
TEXTAREA = {"rows": 3, "class": "w-full rounded border border-slate-600 bg-slate-900 p-2 text-slate-100"}


def _lines(value: str) -> list[str]:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if len(lines) > MAX_COMPONENTS or len(set(lines)) != len(lines):
        raise ValidationError(_("Select at most 100 distinct entries, one per line."))
    return lines


class ComponentSelectionForm(forms.Form):
    target_server = forms.ModelChoiceField(
        queryset=VirtualminServer.objects.none(), label=_("Verified web destination"), widget=PRAHOSelectWidget()
    )
    application_paths = forms.CharField(
        label=_("Application paths"),
        max_length=MAX_COMPONENTS * MAX_PATH_LENGTH,
        initial="public_html",
        help_text=_("One path per line, relative to the source owner's home."),
        widget=forms.Textarea(attrs=TEXTAREA),
    )
    configuration_paths = forms.CharField(
        label=_("Application configuration paths"),
        required=False,
        max_length=MAX_COMPONENTS * MAX_PATH_LENGTH,
        widget=forms.Textarea(attrs=TEXTAREA),
    )
    upload_paths = forms.CharField(
        label=_("Upload paths"),
        required=False,
        max_length=MAX_COMPONENTS * MAX_PATH_LENGTH,
        widget=forms.Textarea(attrs=TEXTAREA),
    )
    databases = forms.CharField(
        label=_("Selected MySQL databases"),
        required=False,
        max_length=MAX_COMPONENTS * 65,
        help_text=_("One database name per line. Leave empty to move files without databases."),
        widget=forms.Textarea(attrs=TEXTAREA),
    )

    def __init__(self, *args: object, account: VirtualminAccount, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]  # Django's polymorphic form constructor.
        self.account = account
        candidates = VirtualminServer.objects.filter(status="active", security_state="verified_web").exclude(
            pk=account.server_id
        )
        eligible = [server.pk for server in candidates if destination_refusal(server) is None]
        target_field = cast("forms.ModelChoiceField[VirtualminServer]", self.fields["target_server"])
        target_field.queryset = VirtualminServer.objects.filter(pk__in=eligible).order_by("name")

    def clean(self) -> dict[str, object]:
        cleaned = cast("dict[str, object]", super().clean() or {})
        if self.account.server.security_state not in {"acknowledged_source_only", "verified_web"}:
            self.add_error(
                None, _("Acknowledge the source services and responsibilities on the node security page first.")
            )
        selected: list[str] = []
        for field in ("application_paths", "configuration_paths", "upload_paths"):
            try:
                lines = _lines(str(cleaned.get(field, "")))
                for relative in lines:
                    path = PurePosixPath(relative)
                    if (
                        len(relative) > MAX_PATH_LENGTH
                        or path.is_absolute()
                        or path.as_posix() != relative
                        or not path.parts
                        or any(part in {".", ".."} or part.startswith(".") for part in path.parts)
                        or path.parts[0].lower() in RESERVED_ROOTS
                        or any(
                            relative == old or relative.startswith(old + "/") or old.startswith(relative + "/")
                            for old in selected
                        )
                    ):
                        raise ValidationError(
                            _(
                                "Select distinct, non-overlapping application paths outside retained mail and system directories."
                            )
                        )
                    selected.append(relative)
            except ValidationError as error:
                self.add_error(field, error)
        if len(selected) > MAX_COMPONENTS:
            self.add_error(None, _("Select at most 100 component paths in total."))
        try:
            if any(
                re.fullmatch(r"[A-Za-z0-9_]{1,64}", name) is None for name in _lines(str(cleaned.get("databases", "")))
            ):
                raise ValidationError(_("Use exact MySQL database names containing letters, numbers or underscores."))
        except ValidationError as error:
            self.add_error("databases", error)
        return cleaned

    def selection(self) -> dict[str, object]:
        return {
            "paths": [
                {"relative": relative, "purpose": purpose}
                for field, purpose in (
                    ("application_paths", "application"),
                    ("configuration_paths", "configuration"),
                    ("upload_paths", "uploads"),
                )
                for relative in _lines(self.cleaned_data.get(field, ""))
            ],
            "databases": _lines(self.cleaned_data.get("databases", "")),
        }


class ComponentApprovalForm(forms.Form):
    review_id = forms.UUIDField(widget=forms.HiddenInput)
    reason = forms.CharField(
        label=_("Migration impact and operator decision"), max_length=2000, widget=forms.Textarea(attrs=TEXTAREA)
    )
    backup_responsibility = forms.CharField(
        label=_("Independent source backup responsibility"),
        max_length=2000,
        help_text=_(
            "Name the operator and existing independent arrangements for retained source mail, DNS and other services. This does not configure PRAHO backups."
        ),
        widget=forms.Textarea(attrs=TEXTAREA),
    )
    impact_accepted = forms.BooleanField(
        label=_(
            "I accept interruption of the selected website and jobs, selected SQL access holds, target activation and routing changes, and the forward-only recovery boundary after native seals."
        ),
        widget=PRAHOCheckboxWidget(),
    )
    retained_responsibility_accepted = forms.BooleanField(
        label=_(
            "I accept continued responsibility for retained source services and their independent backups. Moving the website does not authorize deleting or hardening the source."
        ),
        widget=PRAHOCheckboxWidget(),
    )


class SourceReleaseForm(forms.Form):
    obligation_id = forms.UUIDField(widget=forms.HiddenInput)
    backup_handoff = forms.CharField(
        label=_("Resolved source services and independent backup handoff"),
        max_length=2000,
        widget=forms.Textarea(attrs=TEXTAREA),
    )
    release_accepted = forms.BooleanField(
        label=_(
            "The retained services have been independently resolved and their backups handed over. Verify that the original native domain and every domain using its Unix owner are absent before recording this resolution; do not delete any source resources."
        ),
        widget=PRAHOCheckboxWidget(),
    )
