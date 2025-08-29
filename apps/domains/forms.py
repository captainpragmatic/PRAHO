from django import forms

from .models import Registrar, TLD


class RegistrarForm(forms.ModelForm):
    class Meta:
        model = Registrar
        fields = [
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
        widgets = {
            "default_nameservers": forms.Textarea(attrs={
                "rows": 3,
                "placeholder": '["ns1.example.com", "ns2.example.com"]',
            }),
        }


class TLDForm(forms.ModelForm):
    class Meta:
        model = TLD
        fields = [
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
        widgets = {
            "special_requirements": forms.Textarea(attrs={"rows": 3}),
        }
