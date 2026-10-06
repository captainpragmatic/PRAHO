import json
import re
from typing import Any, ClassVar, cast

from django import forms
from django.utils.translation import gettext_lazy as _

from apps.common.encryption import encrypt_value

from .models import TLD, Registrar


class RegistrarForm(forms.ModelForm):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # ModelForm validation mutates the instance, so capture ciphertext before _post_clean.
        self._existing_secrets: dict[str, str] = {
            "api_key": self.instance.api_key,
            "api_secret": self.instance.api_secret,
            "webhook_secret": self.instance.webhook_secret,
        }
        # Model-derived form.initial takes precedence over field.initial.
        for secret_field in self._existing_secrets:
            if secret_field in self.fields:
                self.initial[secret_field] = ""
                self.fields[secret_field].initial = ""
                self.fields[secret_field].help_text = _("Leave blank to keep the existing secret.")

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

    def clean_default_nameservers(self) -> list[str]:
        value = self.cleaned_data.get("default_nameservers")
        # Accept JSON string or list
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except Exception as e:
                raise forms.ValidationError(_("Invalid JSON for nameservers")) from e

        if not isinstance(value, list):
            raise forms.ValidationError(_("Nameservers must be a list of hostnames"))

        hostname_re = re.compile(
            r"^(?=.{1,253}\.?)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\.?$"
        )
        cleaned: list[str] = []
        for ns in value:
            if not isinstance(ns, str) or not hostname_re.match(ns):
                raise forms.ValidationError(_("Invalid nameserver hostname"))
            cleaned.append(ns.rstrip("."))
        return cleaned

    def save(self, commit: bool = True) -> Registrar:
        instance = super().save(commit=False)
        # Encrypt replacements; blank inputs retain the original ciphertext unchanged.
        for secret_field, existing_secret in self._existing_secrets.items():
            submitted = cast(str, self.cleaned_data.get(secret_field, ""))
            if submitted:
                setattr(instance, secret_field, encrypt_value(submitted) or "")
            else:
                setattr(instance, secret_field, existing_secret)
        if commit:
            instance.save()
        return cast(Registrar, instance)


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
