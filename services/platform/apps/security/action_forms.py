"""Bounded staff action inputs and immutable request identities."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from django import forms
from django.http import QueryDict
from django.utils.translation import gettext_lazy as _

from .forms import FIELD_STYLE
from .models import SecuritySource

SCENARIOS = (
    "crowdsecurity/ssh-bf",
    "crowdsecurity/ssh-bf_user-enum",
    "crowdsecurity/ssh-slow-bf",
    "crowdsecurity/ssh-slow-bf_user-enum",
    "crowdsecurity/ssh-cve-2024-6387",
    "crowdsecurity/http-cve-2021-41773",
    "crowdsecurity/http-cve-2021-42013",
)
MAX_ALLOWLIST_CIDRS = 256


def _proof_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Repeated native proof fact")
        result[key] = value
    return result


if TYPE_CHECKING:
    _SourceChoiceBase = forms.ModelMultipleChoiceField[SecuritySource]
else:
    _SourceChoiceBase = forms.ModelMultipleChoiceField


class SourceMultipleChoiceField(_SourceChoiceBase):
    def label_from_instance(self, obj: SecuritySource) -> str:
        return obj.hostname


class ReasonForm(forms.Form):
    reason = forms.CharField(max_length=2000, label=_("Reason"), widget=forms.Textarea(attrs={"rows": 3}))

    def __init__(self, data: QueryDict | None = None, *, initial: dict[str, object] | None = None) -> None:
        super().__init__(data=data, initial=initial)
        for field in self.fields.values():
            if not isinstance(field.widget, (forms.CheckboxInput, forms.CheckboxSelectMultiple, forms.HiddenInput)):
                field.widget.attrs["class"] = FIELD_STYLE


class ActionHistoryFilter(forms.Form):
    state = forms.ChoiceField(
        required=False,
        label=_("Result"),
        choices=[
            ("", _("All results")),
            ("pending", _("Pending")),
            ("unknown", _("Unknown")),
            ("partial", _("Partial")),
            ("complete", _("Complete")),
            ("superseded", _("Superseded")),
            ("expired", _("Expired")),
            ("rejected", _("Rejected")),
        ],
        widget=forms.Select(attrs={"class": FIELD_STYLE}),
    )


class ActionReasonForm(ReasonForm):
    idempotency_key = forms.UUIDField(initial=uuid4, widget=forms.HiddenInput)


class BanForm(ActionReasonForm):
    sources = SourceMultipleChoiceField(
        queryset=SecuritySource.objects.filter(retired_at__isnull=True).order_by("hostname"), label=_("Target sources")
    )
    address = forms.CharField(max_length=64, label=_("IP address or canonical CIDR"))
    duration_seconds = forms.TypedChoiceField(
        coerce=int,
        initial=14400,
        choices=[(300, _("Five minutes")), (3600, _("One hour")), (14400, _("Four hours"))],
        label=_("Maximum duration"),
    )


class AllowlistForm(ActionReasonForm):
    expected_revision = forms.IntegerField(min_value=0, initial=0, widget=forms.HiddenInput)
    cidrs = forms.CharField(
        max_length=20000,
        required=False,
        label=_("Complete staff allowlist, one CIDR per line"),
        widget=forms.Textarea(attrs={"rows": 8}),
    )

    def clean_cidrs(self) -> list[str]:
        values = [line.strip() for line in self.cleaned_data["cidrs"].splitlines() if line.strip()]
        if len(values) > MAX_ALLOWLIST_CIDRS:
            raise forms.ValidationError(_("Use at most 256 approved networks."))
        return values


class CoverageForm(ReasonForm):
    scenarios = forms.MultipleChoiceField(
        choices=[(value, value) for value in SCENARIOS],
        label=_("Explicitly approved hostile scenarios"),
        widget=forms.CheckboxSelectMultiple,
    )
    evidence_digest = forms.RegexField(regex=r"^[0-9a-f]{64}$", max_length=64, label=_("Native proof SHA-256"))
    native_evidence = forms.CharField(
        max_length=65536, label=_("Qualified native proof JSON"), widget=forms.Textarea(attrs={"rows": 12})
    )
    administrative_ssh = forms.BooleanField(
        required=False, label=_("The acquired SSH journal belongs exclusively to qualified administrative SSH")
    )

    def clean_native_evidence(self) -> dict[str, object]:
        try:
            value = json.loads(self.cleaned_data["native_evidence"], object_pairs_hook=_proof_object)
            json.dumps(value, allow_nan=False)
            if not isinstance(value, dict):
                raise ValueError
        except (ValueError, RecursionError) as error:
            raise forms.ValidationError(
                _("Enter a bounded JSON object containing the qualified native proof.")
            ) from error
        return cast("dict[str, object]", value)
