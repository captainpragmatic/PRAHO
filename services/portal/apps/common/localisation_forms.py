"""Form defaults resolved at construction, never at module import."""

import re
from typing import Any

from django import forms
from django.utils.translation import gettext_lazy as _

from apps.common.localisation import country_name, normalize_country_code
from apps.common.localisation_services import get_localisation_defaults


class CountryDefaultsMixin(forms.BaseForm):
    """Preserve bound input, saved addresses, and explicitly supplied initials."""

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean() or {}
        for prefix in ("", "billing_"):
            if prefix and cleaned.get("billing_same_as_primary"):
                continue
            postal_field = prefix + "postal_code"
            country = cleaned.get(prefix + "country")
            postal_code = cleaned.get(postal_field)
            if normalize_country_code(country) == "RO" and postal_code and not re.fullmatch(r"[0-9]{6}", postal_code):
                self.add_error(postal_field, _("Romanian postal codes must be 6 digits"))
        return cleaned

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        explicit_initial = kwargs.get("initial") or {}
        super().__init__(*args, **kwargs)
        for name in ("country", "billing_country"):
            if name not in self.fields:
                continue
            self.fields[name].widget.attrs.pop("value", None)
            if self.is_bound or name in explicit_initial or getattr(getattr(self, "instance", None), "pk", None):
                continue
            self.initial[name] = country_name(get_localisation_defaults().default_country)
