"""Customer input for buying and spending gift cards."""

from typing import Any, cast

from django import forms
from django.utils.translation import gettext_lazy as _

from apps.ui.templatetags.formatting import cents_to_currency, romanian_currency


class GiftCardPaymentForm(forms.Form):
    document_type = forms.ChoiceField(
        choices=(("invoice", "invoice"), ("proforma", "proforma")), widget=forms.HiddenInput
    )
    document_number = forms.CharField(max_length=100, widget=forms.HiddenInput)
    operation_key = forms.UUIDField(widget=forms.HiddenInput)
    code = forms.CharField(
        max_length=50, label=_("Gift-card code"), widget=forms.TextInput(attrs={"autocomplete": "off"})
    )


class GiftCardPurchaseForm(forms.Form):
    idempotency_key = forms.UUIDField(widget=forms.HiddenInput)
    currency = forms.CharField(widget=forms.HiddenInput)
    currency_revision = forms.IntegerField(min_value=1, widget=forms.HiddenInput)
    amount_cents = forms.TypedChoiceField(label=_("Amount"), coerce=int)
    payment_method = forms.ChoiceField(label=_("Payment method"))
    delivery = forms.ChoiceField(
        label=_("Who is it for?"), choices=(("for_me", _("For me")), ("gift", _("Send as a gift")))
    )
    recipient_email = forms.EmailField(label=_("Recipient email"), required=False, max_length=254)
    recipient_name = forms.CharField(label=_("Recipient name"), required=False, max_length=200)
    recipient_message = forms.CharField(
        label=_("Message (optional)"), required=False, max_length=1000, widget=forms.Textarea(attrs={"rows": 3})
    )

    def __init__(self, *args: Any, catalog: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.is_bound and self.data.get("delivery") == "for_me":
            self.data = {
                **dict(self.data.items()),
                "recipient_email": "",
                "recipient_name": "",
                "recipient_message": "",
            }
        self.catalog = catalog
        cast(forms.ChoiceField, self.fields["amount_cents"]).choices = [
            (cents, romanian_currency(cents_to_currency(cents), catalog["selling_currency"]))
            for cents in catalog["denominations"]
        ]
        labels = {"stripe": _("Card"), "bank": _("Bank transfer")}
        cast(forms.ChoiceField, self.fields["payment_method"]).choices = [
            (method, labels[method]) for method in catalog["payment_methods"]
        ]

    def clean(self) -> dict[str, Any]:
        data = super().clean() or {}
        if (
            data.get("currency") != self.catalog["selling_currency"]
            or data.get("currency_revision") != self.catalog["currency_revision"]
        ):
            raise forms.ValidationError(_("The offer changed. Reload gift cards and review the amount before buying."))
        if data.get("delivery") == "gift" and not data.get("recipient_email"):
            self.add_error("recipient_email", _("Enter the recipient's email address."))
        return data

    def purchase_payload(self) -> dict[str, Any]:
        data = self.cleaned_data
        is_gift = data["delivery"] == "gift"
        return {
            "idempotency_key": str(data["idempotency_key"]),
            "currency": data["currency"],
            "currency_revision": data["currency_revision"],
            "amount_cents": data["amount_cents"],
            "payment_method": data["payment_method"],
            "is_gift": is_gift,
            # The Platform resolves the authenticated buyer when this is not a gift.
            "recipient": {
                "email": data["recipient_email"] if is_gift else "",
                "name": data["recipient_name"] if is_gift else "",
                "message": data["recipient_message"] if is_gift else "",
            },
        }
