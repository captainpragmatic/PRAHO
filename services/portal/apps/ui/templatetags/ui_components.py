"""
PRAHO PLATFORM - UI Components Template Tags
===============================================================================
HTMX-powered reusable components for Romanian hosting provider interface
"""

import re
from dataclasses import dataclass
from typing import Any

from django import template
from django.forms import CheckboxInput, Select, Textarea
from django.template.base import FilterExpression
from django.template.base import token_kwargs as django_token_kwargs
from django.utils.html import format_html, mark_safe  # For XSS prevention
from django.utils.translation import gettext_lazy as _

from apps.common.constants import FILE_SIZE_CONVERSION_FACTOR

register = template.Library()


# ===============================================================================
# UI COMPONENT PARAMETER OBJECTS
# ===============================================================================


@dataclass
class HTMXAttributes:
    """Parameter object for HTMX attributes"""

    hx_get: str | None = None
    hx_post: str | None = None
    hx_put: str | None = None
    hx_patch: str | None = None
    hx_delete: str | None = None
    hx_target: str | None = None
    hx_swap: str | None = None
    hx_trigger: str | None = None
    hx_confirm: str | None = None
    hx_indicator: str | None = None
    hx_push_url: str | None = None
    hx_select: str | None = None
    hx_boost: bool = False


@dataclass
class ButtonConfig:
    """Parameter object for button styling and behavior"""

    variant: str = "primary"
    size: str = "md"
    href: str | None = None
    type: str = "button"
    icon: str | None = None
    icon_right: bool = False
    disabled: bool = False
    class_: str = ""
    attrs: str = ""


@dataclass
class InputConfig:
    """Parameter object for input field configuration"""

    input_type: str = "text"
    value: str | None = None
    label: str | None = None
    placeholder: str | None = None
    required: bool = False
    disabled: bool = False
    readonly: bool = False
    error: str | None = None
    help_text: str | None = None
    icon_left: str | None = None
    icon_right: str | None = None
    css_class: str = ""
    html_id: str | None = None
    options: list[dict[str, Any]] | None = None
    romanian_validation: bool = True


@dataclass
class CheckboxConfig:
    """Parameter object for checkbox configuration"""

    label: str | None = None
    value: str | None = None
    checked: bool = False
    required: bool = False
    disabled: bool = False
    error: str | None = None
    help_text: str | None = None
    variant: str = "primary"
    css_class: str = ""
    container_class: str = ""
    html_id: str | None = None
    data_attrs: dict[str, Any] | None = None


@dataclass
class AlertConfig:
    """Parameter object for alert configuration"""

    variant: str = "info"
    title: str | None = None
    dismissible: bool = False
    show_icon: bool = True
    css_class: str = ""
    html_id: str | None = None


@dataclass
class ModalConfig:
    """Parameter object for modal configuration"""

    size: str = "md"
    closeable: bool = True
    show_footer: bool = True
    content: str | None = None
    css_class: str = ""
    html_id: str | None = None


@dataclass
class BadgeConfig:
    """Parameter object for badge configuration"""

    variant: str = "default"
    size: str = "md"
    rounded: str = "md"
    icon: str | None = None
    icon_position: str = "left"
    dismissible: bool = False
    css_class: str = ""
    html_id: str | None = None


@dataclass
class DataTableConfig:
    """Parameter object for data table configuration"""

    sortable: bool = True
    searchable: bool = True
    pagination: bool = True
    actions: list[dict[str, Any]] | None = None
    css_class: str = ""
    empty_message: str = "No data available."


@register.inclusion_tag("components/button.html")
def button(
    text: str, *, config: ButtonConfig | None = None, htmx: HTMXAttributes | None = None, **kwargs: Any
) -> dict[str, Any]:
    """
    Romanian hosting provider button component with full HTMX support

    Usage:
        {% button "Plătește Factura" variant="success" hx_post="/billing/pay/" %}
        {% button "Adaugă Client" variant="primary" icon="plus" hx_get="/customers/add/" %}
        {% button "Șterge" variant="danger" hx_delete="/api/delete/123" hx_confirm="Ești sigur?" %}

    Args:
        text: Button text (supports Romanian diacritics)
        variant: primary|secondary|success|warning|danger|info
        size: xs|sm|md|lg|xl
        href: Link URL (creates <a> instead of <button>)
        type: Button type (button|submit|reset)
        hx_*: Full HTMX attribute support
        icon: Icon class name
        icon_right: Position icon on the right
        disabled: Disable button
        class_: Additional CSS classes
        attrs: Additional HTML attributes
    """

    # Use default configurations if not provided
    if config is None:
        config = ButtonConfig()
    if htmx is None:
        htmx = HTMXAttributes()

    # Override with any direct kwargs for backward compatibility
    for key, value in kwargs.items():
        if hasattr(config, key) and value is not None:
            setattr(config, key, value)
        elif hasattr(htmx, key) and value is not None:
            setattr(htmx, key, value)

    # 🔒 Security: Escape attrs to prevent XSS attacks
    def _sanitize_and_escape_attrs(raw: Any) -> str:
        s = str(raw or "")

        # Check for truly complex attacks that need more than just escaping
        # Also check for already-encoded versions
        has_complex_payload = any(
            pattern in s.lower()
            for pattern in [
                "onload=",
                "onerror=",
                "onmouseover=",
                "onfocus=",
                "onblur=",  # Auto-executing event handlers
                "javascript:",
                "eval(",
                "atob(",  # Code injection vectors
                "fetch(",
                ".then(",
                "JSON.stringify",  # Network/data exfiltration
                "&lt;script&gt;",
                "alert(1)",  # Already encoded attacks
            ]
        )

        if has_complex_payload:
            # Remove auto-executing dangerous event handlers (but keep onclick as it requires user interaction)
            dangerous_events = r"\b(onload|onerror|onmouseover|onfocus|onblur)\s*="
            s = re.sub(dangerous_events, "", s, flags=re.IGNORECASE)
            # Remove javascript: URLs and code injection
            s = re.sub(r"javascript:[^'\";\s)]*", "", s, flags=re.IGNORECASE)
            s = re.sub(r"\b(eval|alert|atob)\s*\([^)]*\)", "", s, flags=re.IGNORECASE)
            # Handle already encoded dangerous content
            s = re.sub(r"alert\([^)]*\)", "", s, flags=re.IGNORECASE)

        # Manual HTML escaping to return plain string, not SafeString
        s = s.replace("&", "&amp;")
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
        s = s.replace('"', "&quot;")
        s = s.replace("'", "&#x27;")
        return s

    # Return sanitized and escaped attrs
    clean_attrs = _sanitize_and_escape_attrs(config.attrs)

    return {
        "text": text,
        "variant": config.variant,
        "size": config.size,
        "href": config.href,
        "type": config.type,
        "hx_get": htmx.hx_get,
        "hx_post": htmx.hx_post,
        "hx_put": htmx.hx_put,
        "hx_patch": htmx.hx_patch,
        "hx_delete": htmx.hx_delete,
        "hx_target": htmx.hx_target,
        "hx_swap": htmx.hx_swap,
        "hx_trigger": htmx.hx_trigger,
        "hx_confirm": htmx.hx_confirm,
        "hx_indicator": htmx.hx_indicator,
        "hx_push_url": htmx.hx_push_url,
        "hx_select": htmx.hx_select,
        "hx_boost": htmx.hx_boost,
        "icon": config.icon,
        "icon_right": config.icon_right,
        "disabled": config.disabled,
        "class": config.class_,
        "attrs": clean_attrs,
    }


@register.inclusion_tag("components/input.html")
def input_field(
    name: str, *, config: InputConfig | None = None, htmx: HTMXAttributes | None = None, **kwargs: Any
) -> dict[str, Any]:
    """
    Romanian hosting provider input component with HTMX support

    Usage:
        {% input_field "email" label="Email" input_type="email" required=True %}
        {% input_field "search" label="Căutare client" icon_left="search" hx_get="/customers/search/" hx_trigger="keyup changed delay:300ms" %}
    """

    # Use default configurations if not provided
    if config is None:
        config = InputConfig()
    if htmx is None:
        htmx = HTMXAttributes()

    # Override with any direct kwargs for backward compatibility
    for key, value in kwargs.items():
        if hasattr(config, key) and value is not None:
            setattr(config, key, value)
        elif hasattr(htmx, key) and value is not None:
            setattr(htmx, key, value)

    # Auto-generate ID if not provided
    if not config.html_id:
        config.html_id = f"input-{name}"

    return {
        "name": name,
        "input_type": config.input_type,
        "value": config.value,
        "label": config.label,
        "placeholder": config.placeholder,
        "required": config.required,
        "disabled": config.disabled,
        "readonly": config.readonly,
        "error": config.error,
        "help_text": config.help_text,
        "icon_left": config.icon_left,
        "icon_right": config.icon_right,
        "css_class": config.css_class,
        "html_id": config.html_id,
        "hx_get": htmx.hx_get,
        "hx_post": htmx.hx_post,
        "hx_trigger": htmx.hx_trigger,
        "hx_target": htmx.hx_target,
        "hx_swap": htmx.hx_swap,
        "options": config.options,
        "romanian_validation": config.romanian_validation,
        "has_error": bool(config.error),
    }


@register.inclusion_tag("components/checkbox.html")
def checkbox_field(
    name: str, *, config: CheckboxConfig | None = None, htmx: HTMXAttributes | None = None, **kwargs: Any
) -> dict[str, Any]:
    """
    Romanian hosting provider checkbox component with proper text centering

    Usage:
        {% checkbox_field "agree_terms" label="I agree to the terms and conditions" required=True %}
        {% checkbox_field "marketing_consent" label="Send me updates" help_text="Optional newsletter subscription" %}
        {% checkbox_field "confirm_action" label="I understand this action" variant="warning" %}

    Args:
        name: Checkbox input name
        label: Checkbox label text (Romanian text supported)
        value: Checkbox value (default: "on")
        checked: Initial checked state
        required: Mark as required field
        disabled: Disable the checkbox
        error: Error message to display
        help_text: Additional help text below label
        variant: primary|success|warning|danger (affects colors)
        css_class: Additional CSS classes for checkbox
        container_class: Additional CSS classes for container
        html_id: Custom HTML ID (auto-generated if not provided)
        hx_*: HTMX attributes for dynamic behavior
        data_attrs: Dictionary of data attributes
    """

    # Use default configurations if not provided
    if config is None:
        config = CheckboxConfig()
    if htmx is None:
        htmx = HTMXAttributes()

    # Override with any direct kwargs for backward compatibility
    for key, value in kwargs.items():
        if hasattr(config, key) and value is not None:
            setattr(config, key, value)
        elif hasattr(htmx, key) and value is not None:
            setattr(htmx, key, value)

    # Auto-generate ID if not provided
    if not config.html_id:
        config.html_id = f"checkbox-{name}"

    # Default value for checkboxes
    if not config.value:
        config.value = "on"

    return {
        "name": name,
        "label": config.label,
        "value": config.value,
        "checked": config.checked,
        "required": config.required,
        "disabled": config.disabled,
        "error": config.error,
        "help_text": config.help_text,
        "variant": config.variant,
        "css_class": config.css_class,
        "container_class": config.container_class,
        "html_id": config.html_id,
        "hx_get": htmx.hx_get,
        "hx_post": htmx.hx_post,
        "hx_trigger": htmx.hx_trigger,
        "hx_target": htmx.hx_target,
        "hx_swap": htmx.hx_swap,
        "data_attrs": config.data_attrs or {},
    }


@register.inclusion_tag("components/alert.html")
def alert(message: str, *, config: AlertConfig | None = None, **kwargs: Any) -> dict[str, Any]:
    """
    Romanian hosting provider alert component

    Usage:
        {% alert "Factura a fost emisă cu succes!" variant="success" dismissible=True %}
        {% alert "Clientul nu are un VAT ID valid" variant="warning" title="Atenție" %}
    """
    # Use default configuration if not provided
    if config is None:
        config = AlertConfig()

    # Override with any direct kwargs for backward compatibility
    for key, value in kwargs.items():
        if hasattr(config, key) and value is not None:
            setattr(config, key, value)

    return {
        "message": message,
        "variant": config.variant,
        "title": config.title,
        "dismissible": config.dismissible,
        "show_icon": config.show_icon,
        "css_class": config.css_class,
        "html_id": config.html_id,
    }


# ===============================================================================
# FORM-FIELD BRIDGE TAGS (A.1) — Accept Django BoundField objects
# ===============================================================================


@register.inclusion_tag("components/input.html")
def form_field(field: Any, *, icon_left: str | None = None, **kwargs: str) -> dict[str, Any]:
    """
    Bridge tag: renders a Django BoundField via the {% input_field %} component.

    Usage:
        {% form_field form.email icon_left="mail" %}
        {% form_field form.password icon_left="lock" placeholder="Enter password" %}
        {% form_field form.customer_type %}   {# select widget auto-detected #}
    """
    widget = field.field.widget
    name: str = field.html_name
    html_id: str = field.id_for_label or f"id_{name}"

    # ── Detect input_type from widget class ──
    input_type = "text"
    if isinstance(widget, Textarea):
        input_type = "textarea"
    elif isinstance(widget, Select):
        input_type = "select"
    elif isinstance(widget, CheckboxInput):
        input_type = "checkbox"
    else:
        # Honour widget.input_type (email, password, number, etc.)
        wt = getattr(widget, "input_type", "text")
        if wt:
            input_type = wt

    # ── Build options list for <select> ──
    options: list[dict[str, str]] | None = None
    if input_type == "select":
        # choices is list of (value, label) tuples
        choices = getattr(field.field, "choices", [])
        options = [{"value": str(v), "label": str(lbl)} for v, lbl in choices]

    # ── Extract first error (if any) ──
    first_error: str | None = None
    if field.errors:
        first_error = str(field.errors[0])

    # ── Current value ──
    value = field.value()
    value_str: str = str(value) if value is not None else ""

    # ── Label text ──
    label = str(field.label) if field.label else None

    # ── Help text ──
    help_text = str(field.help_text) if field.help_text else None

    return {
        "name": name,
        "input_type": input_type,
        "value": value_str,
        "label": label,
        "placeholder": kwargs.get("placeholder", getattr(widget, "attrs", {}).get("placeholder", "")),
        "required": field.field.required,
        "disabled": kwargs.get("disabled", False),
        "readonly": kwargs.get("readonly", False),
        "error": first_error,
        "help_text": help_text,
        "icon_left": icon_left,
        "icon_right": kwargs.get("icon_right"),
        "css_class": kwargs.get("css_class", ""),
        "html_id": html_id,
        "autocomplete": kwargs.get("autocomplete", getattr(widget, "attrs", {}).get("autocomplete", "")),
        "autofocus": kwargs.get("autofocus", getattr(widget, "attrs", {}).get("autofocus", False)),
        "hx_get": "",
        "hx_post": "",
        "hx_trigger": "",
        "hx_target": "",
        "hx_swap": "",
        "options": options,
        "romanian_validation": False,
        "has_error": bool(first_error),
        "container_class": kwargs.get("container_class", ""),
        "help_text_below": None,
    }


@register.inclusion_tag("components/checkbox.html")
def form_checkbox(field: Any, **kwargs: Any) -> dict[str, Any]:
    """
    Bridge tag: renders a Django BoundField checkbox via {% checkbox_field %}.

    Usage:
        {% form_checkbox form.remember_me %}
        {% form_checkbox form.data_processing_consent %}
    """
    name: str = field.html_name
    html_id: str = field.id_for_label or f"id_{name}"

    first_error: str | None = None
    if field.errors:
        first_error = str(field.errors[0])

    label = str(field.label) if field.label else None
    help_text = str(field.help_text) if field.help_text else None

    # Determine checked state
    value = field.value()
    checked = bool(value) if value is not None else False

    return {
        "name": name,
        "label": kwargs.get("label", label),
        "value": "on",
        "checked": checked,
        "required": field.field.required,
        "disabled": kwargs.get("disabled", False),
        "error": first_error,
        "help_text": help_text,
        "variant": kwargs.get("variant", "primary"),
        "css_class": kwargs.get("css_class", ""),
        "container_class": kwargs.get("container_class", ""),
        "html_id": html_id,
        "hx_get": "",
        "hx_post": "",
        "hx_trigger": "",
        "hx_target": "",
        "hx_swap": "",
        "data_attrs": kwargs.get("data_attrs", {}),
    }


@register.inclusion_tag("components/form_error_summary.html")
def form_error_summary(form: Any) -> dict[str, Any]:
    """
    Render a top-of-form error summary (non-field errors + all field errors).

    Usage:
        {% form_error_summary form %}
    """
    errors: list[str] = []

    # Non-field errors first
    if hasattr(form, "non_field_errors"):
        errors.extend(str(err) for err in form.non_field_errors())

    # Then field-level errors
    if hasattr(form, "errors"):
        for field_name, field_errors in form.errors.items():
            if field_name != "__all__":
                errors.extend(str(err) for err in field_errors)

    return {"errors": errors, "has_errors": bool(errors)}


@register.inclusion_tag("components/modal.html")
def modal(modal_id: str, title: str, *, config: ModalConfig | None = None, **kwargs: Any) -> dict[str, Any]:
    """
    HTMX modal component for Romanian business workflows

    Usage:
        {% modal "invoice-modal" "Factură Nouă" size="lg" %}
        {% modal "confirm-delete" "Confirmare Ștergere" size="sm" %}

    Args:
        modal_id: Unique identifier for the modal
        title: Modal title (Romanian text)
        size: sm|md|lg|xl|full
        closable: Show close button
        backdrop_dismiss: Close on backdrop click
        css_class: Additional CSS classes
    """
    # Use default configuration if not provided
    if config is None:
        config = ModalConfig()

    # Override with any direct kwargs for backward compatibility
    for key, value in kwargs.items():
        if hasattr(config, key) and value is not None:
            setattr(config, key, value)

    # Always resolve a concrete DOM id so JS open/close hooks target the same element.
    resolved_html_id = config.html_id or f"modal-{modal_id or 'default'}"

    return {
        "modal_id": modal_id,
        "title": title,
        "size": config.size,
        "closeable": config.closeable,
        "show_footer": config.show_footer,
        "content": config.content,
        "css_class": config.css_class,
        "html_id": resolved_html_id,
    }


# ===============================================================================
# PAGE-SHELL PRIMITIVES (B.1) — Reusable layout blocks
# ===============================================================================


@dataclass
class PageHeaderConfig:
    """Parameter object for page_header block tag."""

    title: str = ""
    subtitle: str = ""
    icon: str = ""
    css_class: str = ""


class PageHeaderNode(template.Node):
    """Renders a page header with an actions slot between the opening and closing tags."""

    def __init__(
        self,
        kwargs: dict[str, FilterExpression],
        nodelist_actions: template.NodeList,
    ) -> None:
        self.kwargs = kwargs
        self.nodelist_actions = nodelist_actions

    def render(self, context: template.Context) -> str:
        resolved: dict[str, Any] = {k: v.resolve(context) for k, v in self.kwargs.items()}
        actions_html = self.nodelist_actions.render(context)

        t = context.template.engine.get_template("components/page_header.html")
        with context.update(
            {
                "ph_title": resolved.get("title", ""),
                "ph_subtitle": resolved.get("subtitle", ""),
                "ph_icon": resolved.get("icon", ""),
                "ph_css_class": resolved.get("css_class", ""),
                "ph_actions": mark_safe(actions_html),  # noqa: S308  — rendered from Django templates, not user input
            }
        ):
            return t.render(context)  # nosemgrep: direct-use-of-jinja2 — Django Template.render(), not Jinja2


@register.tag("page_header")
def do_page_header(parser: template.base.Parser, token: template.base.Token) -> PageHeaderNode:
    """
    Block tag for standardized page headers with actions slot.

    Usage:
        {% page_header title="Invoice #001" subtitle="Invoice details" icon="document" %}
          <a href="/pdf/">Download PDF</a>
          {% button "Edit" variant="primary" %}
        {% end_page_header %}

        {# Minimal — no actions #}
        {% page_header title="Dashboard" subtitle="Welcome back" %}{% end_page_header %}
    """
    bits = token.split_contents()
    remaining_bits = bits[1:]
    kwargs = django_token_kwargs(remaining_bits, parser)
    if remaining_bits:
        raise template.TemplateSyntaxError(f"{bits[0]} received an invalid argument: {remaining_bits[0]}")

    nodelist = parser.parse(("end_page_header",))
    parser.delete_first_token()
    return PageHeaderNode(kwargs, nodelist)


class SectionCardNode(template.Node):
    """Renders a section card with a content slot between opening and closing tags."""

    def __init__(
        self,
        kwargs: dict[str, FilterExpression],
        nodelist_content: template.NodeList,
    ) -> None:
        self.kwargs = kwargs
        self.nodelist_content = nodelist_content

    def render(self, context: template.Context) -> str:
        resolved: dict[str, Any] = {k: v.resolve(context) for k, v in self.kwargs.items()}
        content_html = self.nodelist_content.render(context)

        t = context.template.engine.get_template("components/section_card.html")
        with context.update(
            {
                "sc_title": resolved.get("title", ""),
                "sc_icon": resolved.get("icon", ""),
                "sc_collapsible": resolved.get("collapsible", False),
                "sc_padding": resolved.get("padding", "p-6"),
                "sc_css_class": resolved.get("css_class", ""),
                "sc_html_id": resolved.get("html_id", ""),
                "sc_content": mark_safe(content_html),  # noqa: S308
            }
        ):
            return t.render(context)  # nosemgrep: direct-use-of-jinja2 — Django Template.render(), not Jinja2


@register.tag("section_card")
def do_section_card(parser: template.base.Parser, token: template.base.Token) -> SectionCardNode:
    """
    Block tag for standardized section cards with titled headers.

    Usage:
        {% section_card title="Customer Details" icon="user" %}
          <p>Card content here...</p>
        {% end_section_card %}

        {% section_card title="Line Items" icon="clipboard" collapsible=True padding="p-4 sm:p-6" %}
          <table>...</table>
        {% end_section_card %}
    """
    bits = token.split_contents()
    remaining_bits = bits[1:]
    kwargs = django_token_kwargs(remaining_bits, parser)
    if remaining_bits:
        raise template.TemplateSyntaxError(f"{bits[0]} received an invalid argument: {remaining_bits[0]}")

    nodelist = parser.parse(("end_section_card",))
    parser.delete_first_token()
    return SectionCardNode(kwargs, nodelist)


@register.inclusion_tag("components/stat_tile.html")
def stat_tile(  # noqa: PLR0913
    label: str,
    value: str,
    *,
    icon: str = "",
    meta: str = "",
    trend: str = "",
    variant: str = "default",
    css_class: str = "",
) -> dict[str, Any]:
    """
    Stat metric tile for dashboards and detail pages.

    Usage:
        {% stat_tile "Total Due" "1.234,56 RON" icon="currency" variant="warning" meta="Due: 15.03.2026" %}
        {% stat_tile "Active Services" "12" icon="server" variant="success" %}
        {% stat_tile "Open Tickets" "3" icon="chat" trend="+2" %}
    """
    return {
        "label": label,
        "value": value,
        "icon": icon,
        "meta": meta,
        "trend": trend,
        "variant": variant,
        "css_class": css_class,
    }


@register.inclusion_tag("components/empty_state.html")
def empty_state(  # noqa: PLR0913
    title: str,
    *,
    icon: str = "inbox",
    body: str = "",
    action_url: str = "",
    action_text: str = "",
    css_class: str = "",
) -> dict[str, Any]:
    """
    Empty state placeholder for lists and tables with no data.

    Usage:
        {% empty_state "No invoices" icon="document" body="No invoices issued yet." action_url="/orders/" action_text="Browse products" %}
        {% empty_state "No tickets" icon="chat" body="You haven't opened any support tickets." %}
    """
    return {
        "title": title,
        "icon": icon,
        "body": body,
        "action_url": action_url,
        "action_text": action_text,
        "css_class": css_class,
    }


# ===============================================================================
# STATUS LABEL / VARIANT / ICON MAPPING (B.3)
# ===============================================================================

# ⚡ O(1) lookup — human-readable labels for statuses that don't title-case well
_STATUS_LABEL_MAP: dict[str, str] = {
    "waiting_on_customer": _("Waiting on You"),
    "in_progress": _("In Progress"),
    "not_consented": _("Not Consented"),
    "not consented": _("Not Consented"),
}

# ⚡ O(1) lookup — all known statuses across billing, services, orders, tickets
_STATUS_VARIANT_MAP: dict[str, str] = {
    # Positive / completed
    "active": "success",
    "paid": "success",
    "healthy": "success",
    "accepted": "success",
    "completed": "success",
    "resolved": "success",
    "granted": "success",
    "converted": "success",
    "enabled": "success",
    "consented": "success",
    # Warning / pending
    "pending": "warning",
    "overdue": "danger",
    "warning": "warning",
    "waiting": "warning",
    "waiting_on_customer": "warning",
    "processing": "info",
    "not consented": "danger",
    # Informational / in-progress
    "draft": "info",
    "issued": "primary",
    "sent": "primary",
    "open": "primary",
    "in_progress": "primary",
    "in progress": "primary",
    "provisioning": "primary",
    # Negative / cancelled
    "cancelled": "danger",
    "suspended": "danger",
    "terminated": "secondary",
    "expired": "danger",
    "void": "secondary",
    "refunded": "warning",
    "error": "danger",
    "revoked": "danger",
    # Neutral / unknown
    "closed": "secondary",
    "inactive": "secondary",
    "unknown": "secondary",
    # Customer membership roles
    "owner": "success",
    "billing": "primary",
    "tech": "info",
    "viewer": "secondary",
}

# ⚡ O(1) lookup — status → icon name (subset with meaningful icons)
_STATUS_ICON_MAP: dict[str, str] = {
    "active": "check",
    "paid": "check",
    "completed": "check",
    "resolved": "check",
    "granted": "check",
    "enabled": "check",
    "healthy": "check",
    "consented": "check",
    "pending": "clock",
    "waiting": "clock",
    "waiting_on_customer": "clock",
    "processing": "clock",
    "expired": "clock",
    "overdue": "alert",
    "warning": "alert",
    "suspended": "ban",
    "cancelled": "x",
    "terminated": "x",
    "error": "alert",
    "revoked": "x",
    "provisioning": "lightning",
    "open": "mail",
    "in_progress": "lightning",
    "in progress": "lightning",
    "draft": "edit",
    "sent": "mail",
    "closed": "x",
}


@register.filter
def status_variant(status: str) -> str:
    """
    Map any status string to a badge variant name.

    Usage:
        {% badge service.status_display variant=service.status|status_variant %}
        {% badge ticket.status_display variant=ticket.status|status_variant rounded="full" %}

    Returns: primary|secondary|success|warning|danger|info|default
    """
    if not status:
        return "secondary"
    return _STATUS_VARIANT_MAP.get(status.lower().strip(), "secondary")


@register.filter
def status_icon(status: str) -> str:
    """
    Map a status string to an icon name for use with {% badge %}.

    Usage:
        {% badge service.status|status_label variant=service.status|status_variant icon=service.status|status_icon %}

    Returns: icon name string or "" if no icon mapped
    """
    if not status:
        return ""
    return _STATUS_ICON_MAP.get(status.lower().strip(), "")


@register.filter
def status_label(status: str) -> str:
    """
    Return a human-readable display label for a raw status code.

    Handles underscore-separated codes (e.g. "waiting_on_customer" → "Waiting on You")
    and falls back to title-cased output for unmapped statuses.

    Usage:
        {% badge ticket.status|status_label variant=ticket.status|status_variant %}
    """
    if not status:
        return ""
    key = status.lower().strip()
    mapped = _STATUS_LABEL_MAP.get(key)
    if mapped:
        return str(mapped)
    return status.replace("_", " ").title()


@register.inclusion_tag("components/table.html")
def data_table(
    headers: list[str], rows: list[list[Any]], *, config: DataTableConfig | None = None, **kwargs: Any
) -> dict[str, Any]:
    """
    Romanian data table component with sorting and pagination

    Usage:
        {% data_table headers=invoice_headers rows=invoice_data sortable=True %}

    Args:
        headers: List of column headers
        rows: List of row data
        sortable: Enable column sorting
        searchable: Enable search functionality
        pagination: Enable pagination
        actions: List of row actions
        css_class: Additional CSS classes
        empty_message: Message when no data
    """
    # Use default configuration if not provided
    if config is None:
        config = DataTableConfig()

    # Override with any direct kwargs for backward compatibility
    for key, value in kwargs.items():
        if hasattr(config, key) and value is not None:
            setattr(config, key, value)

    pagination_obj = kwargs.get("pagination_obj")
    if pagination_obj is None and not isinstance(config.pagination, bool):
        pagination_obj = config.pagination

    show_actions = bool(config.actions)
    if "show_actions" in kwargs:
        show_actions = bool(kwargs["show_actions"])

    return {
        "headers": headers,
        "rows": rows,
        "sortable": config.sortable,
        "searchable": config.searchable,
        "pagination": pagination_obj,
        "show_actions": show_actions,
        "actions": config.actions or [],
        "css_class": config.css_class,
        "empty_message": config.empty_message,
        "has_data": bool(rows),
    }


@register.inclusion_tag("components/toast.html")
def toast(
    message: str,
    *,
    variant: str = "info",
    dismissible: bool = True,
    auto_dismiss: int = 5000,
    toast_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Romanian notification toast component

    Usage:
        {% toast "Factura a fost salvată cu succes!" variant="success" %}
        {% toast "Eroare la procesarea plății." variant="error" %}

    Args:
        message: Toast message (Romanian text)
        variant: success|error|warning|info
        dismissible: Show close button
        auto_dismiss: Auto-dismiss after milliseconds (0 = no auto-dismiss)
        toast_id: Unique identifier
    """
    return {
        "message": message,
        "variant": variant,
        "dismissible": dismissible,
        "auto_dismiss": auto_dismiss,
        "toast_id": toast_id,
    }


@register.inclusion_tag("components/card.html")
def card(
    title: str | None = None,
    *,
    subtitle: str | None = None,
    footer: str | None = None,
    css_class: str = "",
    actions: list[dict[str, Any]] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Romanian business card component

    Usage:
        {% card title="Informații Client" subtitle="Date de contact" %}
        {% card title="Statistici Server" actions=server_actions %}

    Args:
        title: Card title (Romanian text)
        subtitle: Card subtitle
        footer: Card footer content
        css_class: Additional CSS classes
        actions: List of card actions
    """
    return {
        "title": title,
        "subtitle": subtitle,
        "footer": footer,
        "css_class": css_class,
        "actions": actions or [],
        "has_header": bool(title or subtitle or actions),
        "has_footer": bool(footer),
    }


@register.inclusion_tag("components/breadcrumb.html")
def breadcrumb(
    items: list[dict[str, Any]], *, css_class: str = "", separator: str = "/", **kwargs: Any
) -> dict[str, Any]:
    """
    Romanian navigation breadcrumb component

    Usage:
        {% breadcrumb breadcrumb_items %}

    Args:
        items: List of breadcrumb items with 'text' and optional 'url'
        css_class: Additional CSS classes
        separator: Breadcrumb separator character
    """
    return {
        "items": items,
        "css_class": css_class,
        "separator": separator,
    }


_ICON_PATHS: dict[str, str | tuple[str, ...]] = {
    "dashboard": "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6",
    "invoices": "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z",
    "services": "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01",
    "tickets": "M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z",
    "settings": (
        "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z",
        "M15 12a3 3 0 11-6 0 3 3 0 016 0z",
    ),
    "logout": "M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1",
    "check": "M5 13l4 4L19 7",
    "success": "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
    "x": "M6 18L18 6M6 6l12 12",
    "close": "M6 18L18 6M6 6l12 12",
    "warning": "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
    "alert-triangle": "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
    "clock": "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z",
    "lightning": "M13 10V3L4 14h7v7l9-11h-7z",
    "bell": "M15 17h5l-1.405-1.405A2.032 2.032 0 0 1 18 14.158V11a6.002 6.002 0 0 0-4-5.659V4a2 2 0 1 0-4 0v1.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0a3 3 0 1 1-6 0m6 0H9",
    "users": "M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z",
    "user": "M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z",
    "building": "M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-2 10v-5a1 1 0 00-1-1h-2a1 1 0 00-1 1v5m4 0H9",
    "document": "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z",
    "folder-open": "M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1M5 19h14a2 2 0 002-2v-5a2 2 0 00-2-2H9a2 2 0 00-2 2v5a2 2 0 01-2 2z",
    "folder": "M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z",
    "clipboard": "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01",
    "chat": "M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z",
    "receipt": "M9 14l6-6m-5.5.5h.01m4.99 5h.01M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16l3.5-2 3.5 2 3.5-2 3.5 2z",
    "plus": "M12 4v16m8-8H4",
    "minus": "M20 12H4",
    "trash": "M6 7h12m-9 0V5a1 1 0 011-1h4a1 1 0 011 1v2m-7 0l1 12a2 2 0 002 2h2a2 2 0 002-2l1-12",
    "orders": "M16 11V7a4 4 0 00-8 0v4M5 9h14l1 12H4L5 9z",
    "shopping-cart": "M3 3h2l.4 2m0 0h13.2l-1.6 8H6.4M5.4 5L6.4 13m0 0l-1 5h11.6M6.4 13h10.6M9 21a1 1 0 100-2 1 1 0 000 2zm8 0a1 1 0 100-2 1 1 0 000 2z",
    "lock": "M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z",
    "refresh": "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15",
    "loading": "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15",
    "search": "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z",
    "filter": "M3 4a1 1 0 011-1h16a1 1 0 01.8 1.6L14 13.5V19a1 1 0 01-1.447.894l-3-1.5A1 1 0 019 17.5v-4L3.2 4.6A1 1 0 013 4z",
    "sort": "M7 4h10M7 10h7M7 16h4m6 0V6m0 10l-3-3m3 3l3-3",
    "external": "M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14",
    "external-link": "M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14",
    "download": "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4",
    "upload": "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-6l-4-4m0 0L8 10m4-4v12",
    "globe": "M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    "domain": "M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    "server": "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01",
    "mail": "M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z",
    "email": "M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z",
    "arrow-left": "M10 19l-7-7m0 0l7-7m-7 7h18",
    "phone": "M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z",
    "info": "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    "calendar": "M8 7V3m8 4V3m-9 8h10m-12 9h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v11a2 2 0 002 2z",
    "copy": "M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2M10 8h8a2 2 0 012 2v8a2 2 0 01-2 2h-8a2 2 0 01-2-2v-8a2 2 0 012-2z",
    "grid": "M4 6h5v5H4V6zm0 7h5v5H4v-5zm7-7h5v5h-5V6zm0 7h5v5h-5v-5",
    "file-text": "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z",
    "ticket": "M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z",
    "list": "M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01",
    "ban": "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636",
    "credit-card": "M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z",
    "question": "M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    "home": "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6",
    "book": "M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253",
    "chart": "M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z",
    "currency": "M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    # ── A.5 additions: migrated from raw <svg> in feature templates ──
    "chevron-left": "M15 19l-7-7 7-7",
    "chevron-down": "M19 9l-7 7-7-7",
    "chevron-up": "M5 15l7-7 7 7",
    "chevron-right": "M9 5l7 7-7 7",
    "menu": "M4 6h16M4 12h16M4 18h16",
    "arrow-up": "M5 10l7-7m0 0l7 7m-7-7v18",
    "arrow-down": "M19 14l-7 7m0 0l-7-7m7 7V3",
    "arrow-right": "M14 5l7 7m0 0l-7 7m7-7H3",
    "map-pin": (
        "M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z",
        "M15 11a3 3 0 11-6 0 3 3 0 016 0z",
    ),
    "edit": "M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z",
    "exclamation-circle": "M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    "paperclip": "M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13",
    "shield-check": "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z",
    "shield": "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z",
    "star": "M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.801 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.539 1.118l-2.8-2.034a1 1 0 00-1.176 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.719c-.783-.57-.38-1.81.588-1.81H7.03a1 1 0 00.95-.69l1.07-3.292z",
    "key": "M15 7a5 5 0 10-9.95 1H3v2h2v2h2v2h2.05A5.002 5.002 0 0015 7z",
    "swap": "M8 9l4-4 4 4m0 6l-4 4-4-4",
    "pause": "M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z",
    "x-circle": "M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z",
    "danger": "M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z",
    "send": "M12 19l9 2-9-18-9 18 9-2zm0 0v-8",
    "adjustments": (
        "M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4",
    ),
    "flag": "M3 21v-4m0 0V5a2 2 0 012-2h6.5l1 1H21l-3 6 3 6h-8.5l-1-1H5a2 2 0 00-2 2zm9-13.5V9",
    "eye": (
        "M15 12a3 3 0 11-6 0 3 3 0 016 0z",
        "M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z",
    ),
}

_ICON_SIZES: dict[str, str] = {
    "xs": "w-3 h-3",
    "sm": "w-4 h-4",
    "md": "w-5 h-5",
    "lg": "w-6 h-6",
    "xl": "w-8 h-8",
    "2xl": "w-10 h-10",
}


@register.simple_tag
def icon(name: str, *, size: str = "md", css_class: str = "", **kwargs: Any) -> str:
    """
    Inline SVG icon component backed by Heroicons v1 outline paths.

    Usage:
        {% icon "user" size="lg" %}
        {% icon "invoices" css_class="text-blue-400" %}

    Args:
        name: Icon name from _ICON_PATHS catalog
        size: xs|sm|md|lg|xl|2xl
        css_class: Additional CSS classes
    """
    paths = _ICON_PATHS.get(name)
    if paths is None:
        return ""

    classes = f"inline-block {_ICON_SIZES.get(size, _ICON_SIZES['md'])}"
    if css_class:
        classes += f" {css_class}"

    if isinstance(paths, tuple):
        path_html = "".join(
            format_html('<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="{}" />', p)
            for p in paths
        )
    else:
        path_html = format_html(
            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="{}" />', paths
        )

    return format_html(
        '<svg class="{}" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">{}</svg>',
        classes,
        mark_safe(path_html),  # noqa: S308 — path_html built from format_html calls above
    )


@register.simple_tag(takes_context=True)
def active_link(context: Any, url_name: str, css_class: str = "active") -> str:
    """
    Add CSS class if current URL matches the given URL name

    Usage:
        <a href="{% url 'customers:list' %}" class="nav-link {% active_link 'customers:list' %}">

    Args:
        url_name: Django URL name to check
        css_class: CSS class to add if active
    """
    request = context.get("request")
    if request and request.resolver_match:
        current_url_name = request.resolver_match.url_name
        current_namespace = request.resolver_match.namespace

        # Build full URL name with namespace
        full_current = f"{current_namespace}:{current_url_name}" if current_namespace else current_url_name

        if full_current == url_name:
            return css_class

    return ""


@register.simple_tag
def format_bytes(bytes_value: int) -> str:
    """
    Format bytes into human-readable Romanian format

    Usage:
        {% format_bytes 1024 %} -> "1 KB"
        {% format_bytes 1048576 %} -> "1 MB"

    Args:
        bytes_value: Number of bytes
    """
    if bytes_value == 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]
    size: float = float(bytes_value)
    unit_index = 0

    while size >= FILE_SIZE_CONVERSION_FACTOR and unit_index < len(units) - 1:
        size /= FILE_SIZE_CONVERSION_FACTOR
        unit_index += 1

    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.1f} {units[unit_index]}"


@register.inclusion_tag("components/badge.html")
def badge(text: str, *, config: BadgeConfig | None = None, **kwargs: Any) -> dict[str, Any]:
    """
    Romanian hosting provider badge component for status indicators

    Usage:
        {% badge "Pending" variant="warning" icon="clock" %}
        {% badge "Paid" variant="success" icon="check" %}
        {% badge "Overdue" variant="danger" %}
        {% badge "99+" variant="secondary" size="sm" rounded="full" %}

    Args:
        text: Badge text (supports Romanian diacritics and emojis)
        variant: default|primary|secondary|success|warning|danger|info
        size: xs|sm|md|lg
        rounded: sm|md|lg|full
        icon: Icon name (emoji or icon class)
        icon_position: left|right
        dismissible: Show dismiss button
        css_class: Additional CSS classes
        html_id: Custom HTML ID
    """
    # Use default configuration if not provided
    if config is None:
        config = BadgeConfig()

    # Override with any direct kwargs for backward compatibility
    for key, value in kwargs.items():
        if hasattr(config, key) and value is not None:
            setattr(config, key, value)

    # Only use ID if explicitly provided to avoid duplicate IDs
    # Multiple badges with same text would create duplicate IDs otherwise

    return {
        "text": text,
        "variant": config.variant,
        "size": config.size,
        "rounded": config.rounded,
        "icon": config.icon,
        "icon_position": config.icon_position,
        "dismissible": config.dismissible,
        "css_class": config.css_class,
        "html_id": config.html_id,
    }


@register.inclusion_tag("components/nav_dropdown.html")
def dropdown(title: str, items: list[dict[str, Any]], *, icon: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """
    Romanian hosting provider dropdown navigation component

    Usage:
        {% dropdown "Business" business_items icon="building" %}
        {% dropdown "Support" support_items icon="tickets" %}

    Items format:
        [
            {"text": "Customers", "url": "/customers/", "icon": "users"},
            {"divider": True},
            {"text": "Invoices", "url": "/invoices/", "icon": "invoices", "badge": {"text": "3", "variant": "warning"}},
        ]

    Args:
        title: Dropdown button text
        items: List of menu items
        icon: Optional icon for dropdown button
    """
    return {
        "title": title,
        "items": items,
        "icon": icon,
    }


@register.simple_tag
def romanian_percentage(value: float, decimals: int = 1) -> str:
    """
    Format percentage in Romanian style

    Usage:
        {% romanian_percentage 0.19 %} -> "19,0%"
        {% romanian_percentage 0.195 2 %} -> "19,50%"

    Args:
        value: Decimal value (0.19 for 19%)
        decimals: Number of decimal places
    """
    percentage = value * 100
    formatted = f"{percentage:.{decimals}f}".replace(".", ",")
    return f"{formatted}%"


# ===============================================================================
# FORM ACTIONS COMPONENT (A.1)
# ===============================================================================


@register.inclusion_tag("components/form_actions.html")
def form_actions(  # noqa: PLR0913
    submit_label: str = "",
    cancel_url: str = "",
    cancel_label: str = "",
    submit_variant: str = "primary",
    align: str = "right",
    css_class: str = "",
) -> dict[str, Any]:
    """
    Render a standardised form submit/cancel row.

    Usage:
        {% form_actions submit_label="Save Changes" cancel_url=back_url %}
        {% form_actions submit_label="Delete" submit_variant="danger" cancel_url=back_url %}

    Args:
        submit_label:   Text for the submit button (default: "Save").
        cancel_url:     URL for the cancel link; omits cancel when empty.
        cancel_label:   Text for cancel link (default: "Cancel").
        submit_variant: Button colour variant — primary|danger|warning.
        align:          Container alignment — right|left|between.
        css_class:      Extra CSS classes on the container div.
    """
    return {
        "submit_label": submit_label,
        "cancel_url": cancel_url,
        "cancel_label": cancel_label,
        "submit_variant": submit_variant,
        "align": align,
        "css_class": css_class,
    }


@register.inclusion_tag("components/step_progress.html")
def step_progress(  # noqa: PLR0913
    steps: list[dict[str, Any]],
    current_step: int,
    *,
    variant: str = "default",
    color_scheme: str = "blue-green",
    show_back_button: bool = False,
    back_url: str | None = None,
    separator: str = "line",
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Unified step/progress navigation with WCAG accessibility.

    Merges step_navigation, progress_indicator, and order_breadcrumbs into one
    data-driven component with full accessibility (nav, ol/li, aria-current,
    sr-only announcements, aria-live region).

    Args:
        steps: List of step dicts. Each has 'label' (required),
               'description' (optional), 'url' (optional), 'icon' (optional).
        current_step: 1-based index of the active step.
        variant: Layout - 'default', 'compact', or 'vertical'.
        color_scheme: Color theme - 'blue-green', 'purple', or 'red'.
        show_back_button: Whether to show a back navigation button.
        back_url: Explicit back URL. If None and show_back_button is True,
                  derives from the previous step's url or falls back to history.back().
        separator: Between steps - 'line' (horizontal bar) or 'arrow' (chevron icon).

    Usage::

        {% step_progress order_steps current_step=2 separator="arrow" %}
        {% step_progress mfa_steps current_step=1 color_scheme="purple" show_back_button=True %}
    """
    # Derive back URL from previous step if not explicitly provided
    derived_back_url = back_url
    if show_back_button and not back_url and current_step > 1:
        prev_step = steps[current_step - 2] if current_step - 1 < len(steps) else None
        if prev_step and prev_step.get("url"):
            derived_back_url = str(prev_step["url"])

    return {
        "steps": steps,
        "current_step": current_step,
        "total_steps": len(steps),
        "variant": variant,
        "color_scheme": color_scheme,
        "show_back_button": show_back_button,
        "back_url": derived_back_url,
        "separator": separator,
    }
