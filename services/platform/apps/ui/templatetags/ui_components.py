"""
PRAHO PLATFORM - UI Components Template Tags
===============================================================================
HTMX-powered reusable components for Romanian hosting provider interface
"""

import re
from dataclasses import dataclass
from typing import Any

from django import template
from django.utils.html import format_html
from django.utils.safestring import mark_safe  # For XSS prevention

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
    empty_message: str = "Nu există date disponibile."


@dataclass
class EnhancedTableConfig:
    """Parameter object for enhanced table configuration"""

    show_actions: bool = True
    pagination_enabled: bool = True
    include_js: bool = True
    action_column_label: str = ""
    empty_icon: str = "📋"
    empty_title: str = ""
    empty_message: str = ""
    empty_action_url: str = ""
    empty_action_text: str = ""
    htmx_target: str = ""
    htmx_url: str = ""
    css_class: str = ""


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

    return {
        "modal_id": modal_id,
        "title": title,
        "size": config.size,
        "closeable": config.closeable,
        "show_footer": config.show_footer,
        "content": config.content,
        "css_class": config.css_class,
        "html_id": config.html_id,
    }


@register.inclusion_tag("components/table_enhanced.html")
def table_enhanced(
    columns: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    *,
    config: EnhancedTableConfig | None = None,
    page_obj: Any = None,
    extra_params: str = "",
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Modern enhanced table component for PRAHO Platform

    Usage:
        {% table_enhanced columns=billing_columns rows=billing_rows page_obj=documents pagination_enabled=True %}

    Column Structure:
        {
            'label': 'Document Type',
            'width': 'w-28',           # Tailwind width class
            'align': 'center',         # left|center|right
            'sortable': True           # Enable sorting
        }

    Row Structure:
        {
            'clickable': True,
            'click_url': '/billing/invoice/123/',  # Direct URL
            'click_js': 'navigateToDocument("invoice", "123")',  # Custom JS
            'cells': [
                {
                    'component': 'badge',      # badge|button|text
                    'text': 'Invoice',
                    'variant': 'success',
                    'align': 'center',
                    'no_wrap': True,
                    'truncate': False,
                    'title': 'Tooltip text',
                    'text_color': 'text-white',
                    'font_class': 'font-mono'
                }
            ],
            'actions': [
                {
                    'component': 'button',     # button|link
                    'text': '👁️',
                    'variant': 'secondary',
                    'size': 'xs',
                    'href': '/view/123/',
                    'class': 'px-2'
                }
            ]
        }

    Args:
        columns: List of column definitions
        rows: List of row data
        show_actions: Show actions column
        pagination_enabled: Enable pagination
        include_js: Include navigation JavaScript
        page_obj: Django paginator page object
        extra_params: URL parameters for pagination
        htmx_target: HTMX target selector
        htmx_url: HTMX endpoint URL
    """
    # Use default configuration if not provided
    if config is None:
        config = EnhancedTableConfig()

    # Override with any direct kwargs for backward compatibility
    for key, value in kwargs.items():
        if hasattr(config, key) and value is not None:
            setattr(config, key, value)

    return {
        "columns": columns,
        "rows": rows,
        "show_actions": config.show_actions,
        "pagination_enabled": config.pagination_enabled,
        "include_js": config.include_js,
        "action_column_label": config.action_column_label,
        "empty_icon": config.empty_icon,
        "empty_title": config.empty_title,
        "empty_message": config.empty_message,
        "empty_action_url": config.empty_action_url,
        "empty_action_text": config.empty_action_text,
        "htmx_target": config.htmx_target,
        "htmx_url": config.htmx_url,
        "page_obj": page_obj,
        "extra_params": extra_params,
    }


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

    return {
        "headers": headers,
        "rows": rows,
        "sortable": config.sortable,
        "searchable": config.searchable,
        "pagination": config.pagination,
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
    "x": "M6 18L18 6M6 6l12 12",
    "warning": "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
    "clock": "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z",
    "lightning": "M13 10V3L4 14h7v7l9-11h-7z",
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
    "orders": "M16 11V7a4 4 0 00-8 0v4M5 9h14l1 12H4L5 9z",
    "lock": "M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z",
    "refresh": "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15",
    "search": "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z",
    "external": "M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14",
    "download": "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4",
    "globe": "M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    "server": "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01",
    "mail": "M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z",
    "arrow-left": "M10 19l-7-7m0 0l7-7m-7 7h18",
    "phone": "M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z",
    "info": "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    "ban": "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636",
    "credit-card": "M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z",
    "question": "M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    "home": "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6",
    "book": "M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253",
    "chart": "M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z",
    "currency": "M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
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
        mark_safe(path_html),  # Safe: component renders escaped content  # noqa: S308  # Safe: escaped template output
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
        {% dropdown "Business" business_items icon="🏢" %}
        {% dropdown "Support" support_items icon="🎫" %}

    Items format:
        [
            {"text": "Customers", "url": "/customers/", "icon": "👥"},
            {"divider": True},
            {"text": "Invoices", "url": "/invoices/", "icon": "🧾", "badge": {"text": "3", "variant": "warning"}},
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
        {% romanian_percentage 0.21 %} -> "21,0%"
        {% romanian_percentage 0.215 2 %} -> "21,50%"

    Args:
        value: Decimal value (0.21 for 21%)
        decimals: Number of decimal places
    """
    percentage = value * 100
    formatted = f"{percentage:.{decimals}f}".replace(".", ",")
    return f"{formatted}%"
