"""Request-aware date display; no settings reads or network calls per value."""

from django import template
from django.template import Context

from apps.common.localisation import format_localised_date
from apps.common.localisation_services import get_request_localisation

register = template.Library()


@register.simple_tag(takes_context=True)
def localised_date(context: Context, value: object, kind: str = "date") -> str:
    return format_localised_date(value, get_request_localisation(context.get("request")), kind)
