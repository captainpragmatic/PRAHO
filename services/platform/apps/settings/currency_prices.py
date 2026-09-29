"""Staff price entry in explicit currencies, independent of the current storefront."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, cast

from django import forms
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods

from apps.audit.services import AuditService
from apps.billing.currency_policy import get_selling_currency_policy
from apps.common.decorators import billing_configuration_required

if TYPE_CHECKING:
    from apps.domains.models import TLD, TLDRetailPrice
    from apps.products.models import Product, ProductPrice
    from apps.provisioning.service_models import ServicePlan, ServicePlanPrice

    Price = ProductPrice | ServicePlanPrice | TLDRetailPrice
    Entity = Product | ServicePlan | TLD

CURRENCIES = ("RON", "EUR", "USD")
PRICE_FIELDS = {
    "product": ("monthly_price", "quarterly_price", "setup"),
    "plan": ("monthly_price", "quarterly_price", "semiannual_price", "annual_price", "setup"),
    "tld": ("registration_price", "renewal_price", "transfer_price", "whois_privacy_price"),
}
PRICE_LABELS = {
    "monthly_price": _("Monthly price"),
    "quarterly_price": _("Quarterly price"),
    "semiannual_price": _("Six-month price"),
    "annual_price": _("Annual price"),
    "setup": _("Setup fee"),
    "registration_price": _("Registration per year"),
    "renewal_price": _("Renewal per year"),
    "transfer_price": _("Transfer price"),
    "whois_privacy_price": _("WHOIS privacy per year"),
}
OPTIONAL_PRICES = frozenset({"quarterly_price", "semiannual_price", "annual_price"})


def _price_kinds() -> dict[str, tuple[type[models.Model], type[models.Model], str]]:
    """Resolve cross-app model classes when the editor is used, after app loading."""
    from apps.domains.models import TLD, TLDRetailPrice  # noqa: PLC0415  # ADR-0007
    from apps.products.models import Product, ProductPrice  # noqa: PLC0415  # ADR-0007
    from apps.provisioning.service_models import ServicePlan, ServicePlanPrice  # noqa: PLC0415  # ADR-0007

    return {
        "product": (Product, ProductPrice, "product"),
        "plan": (ServicePlan, ServicePlanPrice, "service_plan"),
        "tld": (TLD, TLDRetailPrice, "tld"),
    }


class CurrencyPriceForm(forms.Form):
    version = forms.CharField(required=False, widget=forms.HiddenInput)
    is_active = forms.BooleanField(required=False, initial=True, label=_("Available for new purchases"))

    def __init__(self, *args: Any, kind: str, price: Price | None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.kind = kind
        for name in PRICE_FIELDS[kind]:
            self.fields[name] = forms.DecimalField(
                label=PRICE_LABELS[name],
                decimal_places=2,
                max_digits=14,
                min_value=Decimal(0),
                required=name not in OPTIONAL_PRICES,
            )
            cents = getattr(price, f"{name}_cents", None) if price is not None else None
            self.initial[name] = Decimal(cents) / 100 if cents is not None else (0 if name == "setup" else None)
        if kind == "product":
            for period in ("semiannual", "annual"):
                name = f"{period}_discount_percent"
                self.fields[name] = forms.DecimalField(
                    label=_("Six-month discount (%)") if period == "semiannual" else _("Annual discount (%)"),
                    decimal_places=2,
                    max_digits=5,
                    min_value=Decimal(0),
                    max_value=Decimal(100),
                )
                self.initial[name] = getattr(price, name, 0)
            self.fields["custom_periods"] = forms.CharField(
                label=_("Custom renewal periods"),
                required=False,
                widget=forms.Textarea(attrs={"rows": 4}),
                help_text=_("One period per line: days=price. For example, 45=19.50. Leave empty if not offered."),
            )
            self.initial["custom_periods"] = "\n".join(
                f"{days}={Decimal(cents) / 100:.2f}"
                for days, cents in getattr(price, "custom_period_prices", {}).items()
            )
        self.initial["version"] = price.updated_at.isoformat() if price is not None else ""
        self.initial["is_active"] = price.is_active if price is not None else True
        for field in self.fields.values():
            if not isinstance(field.widget, (forms.HiddenInput, forms.CheckboxInput)):
                field.widget.attrs["class"] = "w-full rounded-lg border border-slate-600 bg-slate-900 p-2 text-white"

    def clean_custom_periods(self) -> dict[str, int]:
        from apps.products.models import validate_custom_period_prices  # noqa: PLC0415  # ADR-0007

        prices: dict[str, int] = {}
        try:
            for line in self.cleaned_data.get("custom_periods", "").splitlines():
                if not line.strip():
                    continue
                days, amount = (part.strip() for part in line.split("="))
                value = Decimal(amount)
                cents = value * 100
                if not value.is_finite() or cents < 0 or cents != cents.to_integral_value() or days in prices:
                    raise ValueError
                prices[days] = int(cents)
            validate_custom_period_prices(prices)
        except (InvalidOperation, ValueError, ValidationError) as exc:
            raise forms.ValidationError(
                _("Use unique periods of 1-730 days and prices with at most two decimals.")
            ) from exc
        return prices

    def price_values(self) -> dict[str, Any]:
        values = {
            f"{name}_cents": int(self.cleaned_data[name] * 100) if self.cleaned_data[name] is not None else None
            for name in PRICE_FIELDS[self.kind]
        }
        values["is_active"] = self.cleaned_data["is_active"]
        if self.kind == "product":
            for field in ("semiannual_discount_percent", "annual_discount_percent"):
                values[field] = self.cleaned_data[field]
            values["custom_period_prices"] = self.cleaned_data["custom_periods"]
        return values


@billing_configuration_required
@require_http_methods(["GET"])
def currency_prices(request: HttpRequest) -> HttpResponse:
    code = request.GET.get("currency", get_selling_currency_policy().currency_code)
    if code not in CURRENCIES:
        raise Http404
    groups = []
    for kind, (entity_model, price_model, relation) in _price_kinds().items():
        prices = {
            str(getattr(price, f"{relation}_id")): price
            for price in price_model._default_manager.filter(currency_id=code)
        }
        groups.append(
            {
                "kind": kind,
                "label": {"product": _("Packages"), "plan": _("Service plans"), "tld": _("Domains")}[kind],
                "rows": [
                    {"entity": entity, "price": prices.get(str(entity.pk))}
                    for entity in entity_model._default_manager.all().order_by("extension" if kind == "tld" else "name")
                ],
            }
        )
    return render(
        request, "settings/currency_prices.html", {"groups": groups, "currency": code, "currencies": CURRENCIES}
    )


@billing_configuration_required
@require_http_methods(["GET", "POST"])
def currency_price_edit(request: HttpRequest, kind: str, entity_id: str, currency: str) -> HttpResponse:
    price_kinds = _price_kinds()
    if kind not in price_kinds or currency not in CURRENCIES:
        raise Http404
    entity_model, price_model, relation = price_kinds[kind]
    try:
        entity = cast("Entity", get_object_or_404(entity_model, pk=entity_id))
    except (ValidationError, ValueError) as exc:
        raise Http404 from exc
    filters = {relation: entity, "currency_id": currency}
    price = cast("Price | None", price_model._default_manager.filter(**filters).first())
    form = CurrencyPriceForm(request.POST or None, kind=kind, price=price)
    response_status = 200
    if request.method == "POST":
        response_status = 400
        if form.is_valid():
            with transaction.atomic():
                get_selling_currency_policy(lock=True)
                current = cast(
                    "Price | None", price_model._default_manager.select_for_update().filter(**filters).first()
                )
                version = current.updated_at.isoformat() if current is not None else ""
                if form.cleaned_data["version"] != version:
                    form.add_error(None, _("This price changed while you were editing. Reload it before saving."))
                    response_status = 409
                else:
                    price = cast("Price", current or price_model(**filters))
                    for field, value in form.price_values().items():
                        setattr(price, field, value)
                    try:
                        price.full_clean()
                    except ValidationError as exc:
                        form.add_error(None, "; ".join(exc.messages))
                    else:
                        price.save()
                        AuditService.log_simple_event(
                            "configuration_changed",
                            content_object=price,
                            user=request.user,
                            description=f"Updated {currency} retail price for {entity}",
                            metadata={"currency": currency, "kind": kind, "entity_id": str(entity.pk)},
                        )
                        messages.success(
                            request, _("The price was saved. Existing purchases keep their recorded terms.")
                        )
                        return redirect(
                            "settings:currency_price_edit", kind=kind, entity_id=entity_id, currency=currency
                        )
    return render(
        request,
        "settings/currency_price_edit.html",
        {
            "form": form,
            "entity": entity,
            "kind": kind,
            "currency": currency,
        },
        status=response_status,
    )
