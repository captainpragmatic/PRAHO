"""Customer input for spending an existing voucher balance."""

from django import forms
from django.utils.translation import gettext_lazy as _


class GiftCardPaymentForm(forms.Form):
    document_type = forms.ChoiceField(
        choices=(("invoice", "invoice"), ("proforma", "proforma")), widget=forms.HiddenInput
    )
    document_number = forms.CharField(max_length=100, widget=forms.HiddenInput)
    operation_key = forms.UUIDField(widget=forms.HiddenInput)
    code = forms.CharField(
        max_length=50, label=_("Gift-card code"), widget=forms.TextInput(attrs={"autocomplete": "off"})
    )
