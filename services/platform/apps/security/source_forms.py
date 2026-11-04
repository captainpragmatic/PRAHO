"""Explicit enrollment never discovers identities or opens host connections."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from uuid import UUID

from django import forms
from django.http import QueryDict
from django.utils.translation import gettext_lazy as _

from .forms import FIELD_STYLE
from .models import SecuritySource
from .services import SourceConfiguration

if TYPE_CHECKING:
    from apps.provisioning.virtualmin_models import VirtualminServer


class SourceReasonForm(forms.Form):
    generation = forms.IntegerField(min_value=1, widget=forms.HiddenInput(attrs={"id": "id_retire_generation"}))
    reason = forms.CharField(
        max_length=2000,
        label=_("Reason"),
        widget=forms.Textarea(attrs={"rows": 3, "class": FIELD_STYLE, "id": "id_retire_reason"}),
    )


class SourceEnrollmentForm(forms.Form):
    kind = forms.ChoiceField(choices=[("node", _("Node")), ("portal", _("Portal"))], label=_("Source kind"))
    transport = forms.ChoiceField(
        choices=[("ssh", _("SSH")), ("local", _("Local staging source"))], label=_("Connection")
    )
    hostname = forms.CharField(max_length=253, label=_("Enrolled hostname"))
    port = forms.IntegerField(min_value=0, max_value=65535, initial=9876, label=_("SSH port (0 for local)"))
    host_keys = forms.CharField(
        max_length=16384,
        required=False,
        label=_("Independently enrolled SSH host keys"),
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    virtualmin_server: forms.ModelChoiceField[VirtualminServer] = forms.ModelChoiceField(
        queryset=None, required=False, label=_("Virtualmin node")
    )
    installation_id = forms.UUIDField(label=_("Physical installation UUID"))
    configuration_digest = forms.RegexField(
        regex=r"^[0-9a-f]{64}$", max_length=64, label=_("Qualified configuration SHA-256")
    )
    sync_enabled = forms.BooleanField(required=False, label=_("Enable synchronization for this source"))
    generation = forms.IntegerField(required=False, min_value=1, widget=forms.HiddenInput)
    reason = forms.CharField(max_length=2000, label=_("Reason"), widget=forms.Textarea(attrs={"rows": 3}))

    def __init__(self, data: QueryDict | None = None, *, source: SecuritySource | None = None) -> None:
        from apps.provisioning.virtualmin_models import (  # noqa: PLC0415 -- ADR-0007: defer node model until form construction
            VirtualminServer,
        )

        initial = (
            None
            if source is None
            else {name: getattr(source, name) for name in self.base_fields if hasattr(source, name)}
        )
        super().__init__(data=data, initial=initial)
        cast(
            "forms.ModelChoiceField[VirtualminServer]", self.fields["virtualmin_server"]
        ).queryset = VirtualminServer.objects.order_by("hostname")
        if source is not None:
            self.fields["generation"].required = True
            for name in ("kind", "virtualmin_server", "installation_id"):
                self.fields[name].disabled = True
        for field in self.fields.values():
            if not isinstance(field.widget, (forms.CheckboxInput, forms.HiddenInput)):
                field.widget.attrs["class"] = FIELD_STYLE

    def configuration(self) -> SourceConfiguration:
        if not self.is_valid():
            raise ValueError("A validated source form is required")
        node = cast("VirtualminServer | None", self.cleaned_data["virtualmin_server"])
        return SourceConfiguration(
            kind=cast("str", self.cleaned_data["kind"]),
            transport=cast("str", self.cleaned_data["transport"]),
            hostname=cast("str", self.cleaned_data["hostname"]),
            port=cast("int", self.cleaned_data["port"]),
            host_keys=cast("str", self.cleaned_data["host_keys"]),
            installation_id=cast("UUID", self.cleaned_data["installation_id"]),
            configuration_digest=cast("str", self.cleaned_data["configuration_digest"]),
            sync_enabled=cast("bool", self.cleaned_data["sync_enabled"]),
            virtualmin_server_id=node.pk if node else None,
        )
