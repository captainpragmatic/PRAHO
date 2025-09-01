from typing import ClassVar
import json
import re

from django import forms

from .models import TLD, Registrar


class RegistrarForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Do not prefill sensitive fields
        for secret_field in ("api_key", "api_secret", "webhook_secret"):
            if secret_field in self.fields:
                self.fields[secret_field].initial = ""

    class Meta:
        model = Registrar
        fields: ClassVar = [
            "display_name",
            "name",
            "website_url",
            "api_endpoint",
            "api_username",
            "api_key",
            "api_secret",
            "webhook_secret",
            "webhook_endpoint",
            "status",
            "default_nameservers",
            "currency",
            "monthly_fee_cents",
        ]
        widgets: ClassVar = {
            "default_nameservers": forms.Textarea(
                attrs={
                    "rows": 3,
                    "placeholder": '["ns1.example.com", "ns2.example.com"]',
                }
            ),
        }

    def clean_default_nameservers(self):
        value = self.cleaned_data.get("default_nameservers")
        # Accept JSON string or list
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except Exception:
                raise forms.ValidationError("Invalid JSON for nameservers")

        if not isinstance(value, list):
            raise forms.ValidationError("Nameservers must be a list of hostnames")

        hostname_re = re.compile(r"^(?=.{1,253}\.?)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\.?$")
        cleaned: list[str] = []
        for ns in value:
            if not isinstance(ns, str) or not hostname_re.match(ns):
                raise forms.ValidationError("Invalid nameserver hostname")
            cleaned.append(ns.rstrip('.'))
        return cleaned

    def save(self, commit=True):
        from apps.settings.encryption import settings_encryption
        instance = super().save(commit=False)
        # Encrypt secrets at rest
        if self.cleaned_data.get("api_key"):
            instance.api_key = settings_encryption.encrypt_value(self.cleaned_data["api_key"]) or ""
        if self.cleaned_data.get("api_secret"):
            instance.api_secret = settings_encryption.encrypt_value(self.cleaned_data["api_secret"]) or ""
        # webhook_secret may be used raw by webhooks; keep as provided (write-only)
        if commit:
            instance.save()
        return instance


class TLDForm(forms.ModelForm):
    class Meta:
        model = TLD
        fields: ClassVar = [
            # Core
            "extension",
            "description",
            # Pricing
            "registration_price_cents",
            "renewal_price_cents",
            "transfer_price_cents",
            "registrar_cost_cents",
            # Config
            "min_registration_period",
            "max_registration_period",
            # Features
            "whois_privacy_available",
            "grace_period_days",
            "redemption_fee_cents",
            # Romanian-specific
            "requires_local_presence",
            "special_requirements",
            # Status
            "is_active",
            "is_featured",
        ]
        widgets: ClassVar = {
            "special_requirements": forms.Textarea(attrs={"rows": 3}),
        }
