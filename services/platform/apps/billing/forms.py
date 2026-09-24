"""Forms for staff-managed billing domain policy."""

from __future__ import annotations

from typing import Any

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .ec_sales_service import ReportingPeriod
from .payment_models import PaymentRetryPolicy

_INPUT_CLASS = (
    "w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-slate-100 "
    "focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40"
)
_CHECKBOX_CLASS = "h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500"


class D390PeriodForm(forms.Form):
    month = forms.DateField(
        label=_("Reporting month"),
        input_formats=["%Y-%m"],
        widget=forms.DateInput(format="%Y-%m", attrs={"type": "month", "class": _INPUT_CLASS}),
    )

    def clean_month(self) -> ReportingPeriod:
        month = self.cleaned_data["month"]
        try:
            return ReportingPeriod(month.year, month.month)
        except ValueError as exc:
            raise ValidationError(_("Choose a month from February 2020 through December 2100.")) from exc


class D390ExportForm(D390PeriodForm):
    action = forms.ChoiceField(choices=[("csv", "CSV"), ("xml", "XML")], widget=forms.HiddenInput)
    source_fingerprint = forms.CharField(min_length=64, max_length=64, widget=forms.HiddenInput)
    surname = forms.CharField(label=_("Declarant surname"), max_length=75, required=False)
    given_name = forms.CharField(label=_("Declarant given name"), max_length=75, required=False)
    role = forms.CharField(label=_("Declarant role"), max_length=50, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["month"].widget = forms.HiddenInput(attrs={"id": "id_export_month"})
        _style_form_fields(self)

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean() or {}
        if cleaned.get("action") == "xml":
            for field in ("surname", "given_name", "role"):
                if not cleaned.get(field):
                    self.add_error(field, _("Required for XML export."))
        return cleaned


class PaymentRetryPolicyForm(forms.Form):
    """Human-friendly editor for the live retry-policy fields."""

    name = forms.CharField(max_length=100)
    description = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 3}))
    retry_intervals_days = forms.CharField(
        label=_("Retry days"),
        help_text=_("Strictly increasing days from the original payment failure, for example: 1, 3, 7, 14."),
    )
    max_attempts = forms.IntegerField(min_value=1, max_value=10)
    send_dunning_emails = forms.BooleanField(required=False)
    is_default = forms.BooleanField(required=False)
    is_active = forms.BooleanField(required=False)
    reason = forms.CharField(
        max_length=500,
        help_text=_("Required audit reason for changing a collection policy."),
    )
    baseline = forms.CharField(widget=forms.HiddenInput)

    def __init__(self, *args: Any, instance: PaymentRetryPolicy, **kwargs: Any) -> None:
        self.instance = instance
        initial = {
            "name": instance.name,
            "description": instance.description,
            "retry_intervals_days": ", ".join(str(day) for day in instance.retry_intervals_days),
            "max_attempts": instance.max_attempts,
            "send_dunning_emails": instance.send_dunning_emails,
            "is_default": instance.is_default,
            "is_active": instance.is_active,
            "baseline": instance.updated_at.isoformat(),
        }
        initial.update(kwargs.pop("initial", {}))
        super().__init__(*args, initial=initial, **kwargs)
        _style_form_fields(self)

    def clean_retry_intervals_days(self) -> list[int]:
        raw_value = self.cleaned_data["retry_intervals_days"]
        try:
            return [int(part.strip()) for part in raw_value.split(",") if part.strip()]
        except ValueError as exc:
            raise ValidationError(_("Retry days must be comma-separated whole numbers.")) from exc

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean() or {}
        required_fields = {
            "name",
            "retry_intervals_days",
            "max_attempts",
            "send_dunning_emails",
            "is_default",
            "is_active",
        }
        if required_fields.issubset(cleaned):
            # Only the fields this form exposes participate in validation; the
            # dormant suspend/terminate escalation columns are not copied.
            candidate = PaymentRetryPolicy(pk=self.instance.pk)
            for field_name in (
                "name",
                "description",
                "retry_intervals_days",
                "max_attempts",
                "send_dunning_emails",
                "is_default",
                "is_active",
            ):
                setattr(candidate, field_name, cleaned.get(field_name))
            try:
                candidate.clean()
            except ValidationError as exc:
                for field_name, errors in exc.message_dict.items():
                    for error in errors:
                        self.add_error(field_name if field_name in self.fields else None, error)
        if cleaned.get("is_default") and not cleaned.get("is_active"):
            self.add_error("is_active", _("The default retry policy must be active."))
        return cleaned


class InvoiceSeriesForm(forms.Form):
    """Guarded rotation form; the next sequence value is intentionally absent."""

    prefix = forms.RegexField(
        regex=r"^[A-Z0-9][A-Z0-9-]{0,29}$",
        max_length=30,
        help_text=_("Uppercase letters, digits, and hyphens only; for example INV-2027."),
        error_messages={"invalid": _("Use uppercase letters, digits, and hyphens only.")},
    )
    confirmation = forms.CharField(
        max_length=30,
        help_text=_("Type the new prefix exactly to confirm the series rotation."),
    )
    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text=_("Required legal and audit reason for starting this invoice series."),
    )
    baseline = forms.CharField(max_length=64, widget=forms.HiddenInput)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _style_form_fields(self)

    def clean_prefix(self) -> str:
        return str(self.cleaned_data["prefix"]).strip().upper()

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean() or {}
        prefix = cleaned.get("prefix")
        confirmation = (cleaned.get("confirmation") or "").strip()
        if prefix and confirmation != prefix:
            self.add_error("confirmation", _("The confirmation must exactly match the new prefix."))
        return cleaned


def _style_form_fields(form: forms.Form) -> None:
    """Apply the shared dark-theme controls without styling hidden baselines."""
    for field in form.fields.values():
        if field.widget.is_hidden:
            continue
        css_class = _CHECKBOX_CLASS if isinstance(field.widget, forms.CheckboxInput) else _INPUT_CLASS
        field.widget.attrs["class"] = css_class


class ProviderReconciliationForm(forms.Form):
    """Adopt a provider document an operator found by hand.

    Deliberately asks for the number twice. The provider exposes no lookup by our
    reference, so this number is a human's reading of a screen, and it is about to
    become a legal fiscal number that cannot be changed afterwards. The confirmation
    field is the same guard `InvoiceSeriesForm` puts on a series rotation, for the
    same reason.
    """

    series = forms.CharField(
        max_length=30,
        required=False,
        help_text=_("Series exactly as the provider shows it, or blank if it has none."),
    )
    number = forms.CharField(
        max_length=50,
        help_text=_("Document number exactly as the provider shows it."),
    )
    confirmation = forms.CharField(
        max_length=50,
        help_text=_("Type the document number again to confirm."),
    )
    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text=_("What you checked at the provider, and how you identified this document."),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _style_form_fields(self)

    def clean_series(self) -> str:
        return str(self.cleaned_data.get("series") or "").strip()

    def clean_number(self) -> str:
        return str(self.cleaned_data["number"]).strip()

    def clean(self) -> dict[str, Any]:
        from .invoice_models import Invoice  # noqa: PLC0415  # deferred: forms is imported early

        cleaned = super().clean() or {}
        number = cleaned.get("number")
        confirmation = (cleaned.get("confirmation") or "").strip()
        if number and confirmation != number:
            self.add_error("confirmation", _("The confirmation must exactly match the document number."))

        # Composed exactly as `reconcile_confirmed_issued` composes it, and measured
        # against the column rather than a literal, so the two cannot drift apart. The
        # field limits are checked separately and never see the join: a 30-character
        # series with a 50-character number is valid twice over and 81 characters once,
        # which PostgreSQL answers with a DataError - a 500 instead of a field error, on
        # the one screen whose output cannot be changed afterwards.
        series = (cleaned.get("series") or "").strip()
        if number:
            legal_number = f"{series}-{number}" if series else number
            limit = Invoice._meta.get_field("number").max_length
            if limit is not None and len(legal_number) > limit:
                self.add_error(
                    "number",
                    _("Series and number together make %(length)d characters; the legal number allows %(limit)d.")
                    % {"length": len(legal_number), "limit": limit},
                )
        return cleaned
