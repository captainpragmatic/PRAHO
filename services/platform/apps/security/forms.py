"""Bounded filters over Platform's stored security summaries."""

from __future__ import annotations

import ipaddress
from typing import cast

from django import forms
from django.http import QueryDict
from django.utils.translation import gettext_lazy as _

from .models import SecuritySource

FIELD_STYLE = "w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-slate-100"


class SecurityFilterForm(forms.Form):
    source = forms.ModelChoiceField(queryset=SecuritySource.objects.none(), required=False, label=_("Source"))
    address = forms.CharField(max_length=64, required=False, label=_("IP address or network"))
    scenario = forms.CharField(max_length=200, required=False, label=_("Scenario"))
    scope = forms.ChoiceField(
        required=False,
        choices=[("", _("All scopes")), ("ip", _("IP addresses")), ("range", _("Networks"))],
        label=_("Scope"),
    )
    state = forms.ChoiceField(
        required=False,
        initial="active",
        choices=[("active", _("Active decisions")), ("ended", _("Ended decisions")), ("all", _("All decisions"))],
        label=_("State"),
    )
    simulated = forms.ChoiceField(
        required=False,
        choices=[("", _("All alerts")), ("yes", _("Simulated alerts")), ("no", _("Other alerts"))],
        label=_("Alerts"),
    )

    def __init__(self, data: QueryDict | None = None) -> None:
        super().__init__(data=data)
        source_field = cast("forms.ModelChoiceField[SecuritySource]", self.fields["source"])
        source_field.queryset = SecuritySource.objects.order_by("hostname", "created_at")
        source_field.label_from_instance = lambda source: source.hostname
        for field in self.fields.values():
            field.widget.attrs["class"] = FIELD_STYLE

    def clean_address(self) -> str:
        value = str(self.cleaned_data.get("address", "")).strip()
        if not value:
            return ""
        try:
            if "%" in value:
                raise ValueError
            return str(ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value))
        except ValueError as error:
            raise forms.ValidationError(_("Enter a valid IPv4 or IPv6 address or network.")) from error
