"""Forms for staff-managed billing domain policy."""

from __future__ import annotations

from typing import Any

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .payment_models import PaymentRetryPolicy

_INPUT_CLASS = (
    "w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-slate-100 "
    "focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40"
)
_CHECKBOX_CLASS = "h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500"


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
            candidate = PaymentRetryPolicy(pk=self.instance.pk)
            candidate.suspend_service_after_days = self.instance.suspend_service_after_days
            candidate.terminate_service_after_days = self.instance.terminate_service_after_days
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
