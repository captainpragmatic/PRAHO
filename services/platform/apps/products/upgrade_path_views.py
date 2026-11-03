"""Staff graph inspection and the existing administrator-only catalog editing policy."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from django import forms
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods, require_POST

from apps.common.decorators import admin_required, is_administrator, staff_required_strict

from .models import Product, ProductRelationship
from .upgrade_paths import UPGRADE_RELATIONSHIP, remove_upgrade_path, save_upgrade_path

if TYPE_CHECKING:
    from apps.users.models import User


class UpgradePathForm(forms.Form):
    target_product = forms.ModelChoiceField(queryset=Product.objects.none(), label=_("Upgrade target"))
    sort_order = forms.IntegerField(min_value=0, max_value=2**31 - 1, initial=0, label=_("Display order"))
    is_active = forms.BooleanField(required=False, initial=True, label=_("Active"))

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        cast("forms.ModelChoiceField[Product]", self.fields["target_product"]).queryset = Product.objects.order_by(
            "name", "pk"
        )
        for field in self.fields.values():
            field.widget.attrs["class"] = (
                "rounded border-slate-600 bg-slate-700 text-white"
                if isinstance(field.widget, forms.CheckboxInput)
                else "block w-full rounded border border-slate-600 bg-slate-700 text-white px-3 py-2"
            )


@staff_required_strict
@require_http_methods(["GET"])
def upgrade_paths(request: HttpRequest, slug: str) -> HttpResponse:
    product = get_object_or_404(Product, slug=slug)
    edges = ProductRelationship.objects.filter(relationship_type=UPGRADE_RELATIONSHIP)
    return render(
        request,
        "products/upgrade_paths.html",
        {
            "product": product,
            "forward_paths": edges.filter(source_product=product).select_related("target_product"),
            "reverse_paths": edges.filter(target_product=product).select_related("source_product"),
            "can_manage_catalog": is_administrator(request.user),
        },
    )


@admin_required
@require_http_methods(["GET", "POST"])
def upgrade_path_edit(request: HttpRequest, slug: str, relationship_id: UUID | None = None) -> HttpResponse:
    product = get_object_or_404(Product, slug=slug)
    edge = None
    if relationship_id is not None:
        edge = get_object_or_404(
            ProductRelationship, pk=relationship_id, source_product=product, relationship_type=UPGRADE_RELATIONSHIP
        )
    form = UpgradePathForm(
        request.POST if request.method == "POST" else None,
        initial={"target_product": edge.target_product_id, "sort_order": edge.sort_order, "is_active": edge.is_active}
        if edge is not None
        else None,
    )
    if request.method == "POST" and form.is_valid():
        try:
            save_upgrade_path(
                actor=cast("User", request.user),
                source_product_id=product.pk,
                target_product_id=form.cleaned_data["target_product"].pk,
                relationship_id=relationship_id,
                is_active=form.cleaned_data["is_active"],
                sort_order=form.cleaned_data["sort_order"],
            )
        except ValidationError as error:
            form.add_error(None, error)
        except (Product.DoesNotExist, ProductRelationship.DoesNotExist) as error:
            raise Http404 from error
        else:
            messages.success(request, _("Upgrade path saved."))
            return redirect("products:upgrade_paths", slug=product.slug)
    return render(
        request,
        "products/upgrade_path_form.html",
        {"product": product, "edge": edge, "form": form},
        status=400 if request.method == "POST" else 200,
    )


@admin_required
@require_POST
def upgrade_path_remove(request: HttpRequest, slug: str, relationship_id: UUID) -> HttpResponse:
    product = get_object_or_404(Product, slug=slug)
    try:
        remove_upgrade_path(
            actor=cast("User", request.user), source_product_id=product.pk, relationship_id=relationship_id
        )
    except ProductRelationship.DoesNotExist as error:
        raise Http404 from error
    messages.success(request, _("Upgrade path removed."))
    return redirect("products:upgrade_paths", slug=product.slug)
