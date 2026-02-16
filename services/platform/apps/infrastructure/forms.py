"""
Infrastructure Forms

Django forms for node deployment management.
"""

from django import forms
from django.core.exceptions import ValidationError

from apps.infrastructure.models import (
    CloudProvider,
    NodeDeployment,
    NodeRegion,
    NodeSize,
    PanelType,
)


class NodeDeploymentForm(forms.ModelForm):
    """Form for creating new node deployments"""

    class Meta:
        model = NodeDeployment
        fields = [
            "environment",
            "node_type",
            "provider",
            "region",
            "node_size",
            "panel_type",
            "display_name",
            "backup_enabled",
        ]
        widgets = {
            "environment": forms.RadioSelect(attrs={"class": "sr-only peer", "x-model": "environment"}),
            "node_type": forms.RadioSelect(attrs={"class": "sr-only peer", "x-model": "nodeType"}),
            "provider": forms.Select(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white",
                    "x-model": "provider",
                    "@change": "updateRegions()",
                }
            ),
            "region": forms.Select(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white",
                    "x-model": "region",
                }
            ),
            "node_size": forms.RadioSelect(attrs={"class": "sr-only peer", "x-model": "nodeSize"}),
            "panel_type": forms.Select(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white",
                }
            ),
            "display_name": forms.TextInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "placeholder": "Optional friendly name for this node",
                }
            ),
            "backup_enabled": forms.CheckboxInput(
                attrs={
                    "class": "rounded bg-slate-700 border-slate-600 text-blue-500 focus:ring-blue-500",
                }
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Filter to only active providers
        self.fields["provider"].queryset = CloudProvider.objects.filter(is_active=True)

        # Filter to only active panel types
        self.fields["panel_type"].queryset = PanelType.objects.filter(is_active=True)

        # Initially show all active regions (will be filtered by JS based on provider)
        self.fields["region"].queryset = NodeRegion.objects.filter(is_active=True).select_related("provider")

        # Initially show all active sizes (will be filtered by JS based on provider)
        self.fields["node_size"].queryset = NodeSize.objects.filter(is_active=True).select_related("provider")

        # Set defaults
        self.fields["backup_enabled"].initial = True

    def clean(self):
        cleaned_data = super().clean()
        provider = cleaned_data.get("provider")
        region = cleaned_data.get("region")
        node_size = cleaned_data.get("node_size")

        # Validate region belongs to selected provider
        if provider and region and region.provider != provider:
            raise ValidationError({"region": "Selected region does not belong to the selected provider"})

        # Validate size belongs to selected provider
        if provider and node_size and node_size.provider != provider:
            raise ValidationError({"node_size": "Selected size does not belong to the selected provider"})

        return cleaned_data


class CloudProviderForm(forms.ModelForm):
    """Form for managing cloud providers"""

    api_token = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                "placeholder": "API Token",
            }
        ),
        required=False,
        help_text="Leave blank to keep existing token",
    )

    class Meta:
        model = CloudProvider
        fields = ["name", "provider_type", "code", "is_active", "config"]
        widgets = {
            "name": forms.TextInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "placeholder": "Provider Name",
                }
            ),
            "provider_type": forms.Select(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white",
                }
            ),
            "code": forms.TextInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "placeholder": "3-letter code (e.g., het)",
                    "maxlength": "3",
                }
            ),
            "is_active": forms.CheckboxInput(
                attrs={
                    "class": "rounded bg-slate-700 border-slate-600 text-blue-500 focus:ring-blue-500",
                }
            ),
            "config": forms.Textarea(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2 font-mono text-sm",
                    "rows": 4,
                    "placeholder": '{"key": "value"}',
                }
            ),
        }


class NodeSizeForm(forms.ModelForm):
    """Form for managing node sizes"""

    class Meta:
        model = NodeSize
        fields = [
            "provider",
            "name",
            "display_name",
            "provider_type_id",
            "vcpus",
            "memory_gb",
            "disk_gb",
            "hourly_cost_eur",
            "monthly_cost_eur",
            "max_domains",
            "max_bandwidth_gb",
            "is_active",
            "sort_order",
        ]
        widgets = {
            "provider": forms.Select(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white",
                }
            ),
            "name": forms.TextInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "placeholder": "Small, Medium, Large",
                }
            ),
            "display_name": forms.TextInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "placeholder": "2 vCPU / 4GB RAM / 40GB",
                }
            ),
            "provider_type_id": forms.TextInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "placeholder": "cpx21",
                }
            ),
            "vcpus": forms.NumberInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "min": "1",
                }
            ),
            "memory_gb": forms.NumberInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "min": "1",
                }
            ),
            "disk_gb": forms.NumberInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "min": "10",
                }
            ),
            "hourly_cost_eur": forms.NumberInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "step": "0.0001",
                }
            ),
            "monthly_cost_eur": forms.NumberInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "step": "0.01",
                }
            ),
            "max_domains": forms.NumberInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "min": "1",
                }
            ),
            "max_bandwidth_gb": forms.NumberInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "min": "100",
                }
            ),
            "is_active": forms.CheckboxInput(
                attrs={
                    "class": "rounded bg-slate-700 border-slate-600 text-blue-500 focus:ring-blue-500",
                }
            ),
            "sort_order": forms.NumberInput(
                attrs={
                    "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                    "min": "0",
                }
            ),
        }


class DeploymentDestroyForm(forms.Form):
    """Form for confirming deployment destruction"""

    confirm_hostname = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "w-full bg-slate-700 border-slate-600 rounded-lg text-white px-4 py-2",
                "placeholder": "Type the hostname to confirm",
            }
        ),
        help_text="Type the hostname exactly to confirm destruction",
    )

    def __init__(self, *args, hostname: str = "", **kwargs):
        self.expected_hostname = hostname
        super().__init__(*args, **kwargs)

    def clean_confirm_hostname(self):
        confirm = self.cleaned_data["confirm_hostname"]
        if confirm != self.expected_hostname:
            raise ValidationError(f"Hostname must match exactly: {self.expected_hostname}")
        return confirm
