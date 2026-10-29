"""Zone imports and revision-bound customer record changes."""

from typing import Any

from django import forms
from django.utils.translation import gettext_lazy as _

from .services import MAX_ZONE_FILE_BYTES, RECORD_TYPES


class ZoneImportForm(forms.Form):
    service_id = forms.IntegerField(min_value=1, widget=forms.HiddenInput)
    zone_file = forms.FileField(label=_("Zone file"), help_text=_("Upload a complete BIND zone file, up to 2 MiB."))

    def clean_zone_file(self) -> Any:
        uploaded = self.cleaned_data["zone_file"]
        if not uploaded.size or uploaded.size > MAX_ZONE_FILE_BYTES:
            raise forms.ValidationError(_("Upload a zone file of at most 2 MiB."))
        return uploaded


class RevisionForm(forms.Form):
    expected_revision = forms.IntegerField(min_value=1, widget=forms.HiddenInput)


class ConfirmImportForm(RevisionForm):
    manifest_digest = forms.RegexField(r"^[0-9a-f]{64}$", widget=forms.HiddenInput)
    confirmed = forms.BooleanField(label=_("I reviewed every page of the imported records and proposed changes."))


class RegistrarSwitchForm(RevisionForm):
    confirmed = forms.BooleanField(label=_("Update the nameservers at my registrar to the complete list shown above."))


class DeleteZoneForm(RevisionForm):
    export_digest = forms.RegexField(r"^[0-9a-f]{64}$", widget=forms.HiddenInput)
    moved_away = forms.BooleanField(
        label=_("I moved DNS to another provider and understand that independent checks must confirm it.")
    )
    confirmed = forms.BooleanField(label=_("Request deletion of this DNS zone after the safety checks pass."))


class DeleteRecordForm(RevisionForm):
    confirmed = forms.BooleanField(label=_("Delete this record from the DNS zone."))


class RecordForm(RevisionForm):
    name = forms.CharField(max_length=253, label=_("Record name"), help_text=_("Use a full DNS name within this zone."))
    record_type = forms.ChoiceField(choices=[(kind, kind) for kind in RECORD_TYPES], label=_("Record type"))
    rdata = forms.CharField(
        max_length=4096,
        label=_("Value in DNS notation"),
        strip=False,
        help_text=_(
            "A/AAAA: address. MX: priority target. TXT: quoted text. SRV: priority weight port target. CAA: flags tag quoted-value."
        ),
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    ttl = forms.IntegerField(min_value=60, max_value=86400, initial=300, label=_("TTL (seconds)"))

    def payload(self) -> dict[str, Any]:
        return {key: self.cleaned_data[key] for key in ("expected_revision", "name", "record_type", "rdata", "ttl")}
