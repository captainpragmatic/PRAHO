"""
PRAHO PLATFORM - UI Components Template Tags
===============================================================================
HTMX-powered reusable components for Romanian hosting provider interface
"""

import re
from dataclasses import dataclass
from typing import Any

from django import template
from django.utils.html import format_html  # For XSS prevention

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


@register.simple_tag
def icon(name: str, *, size: str = "md", css_class: str = "", **kwargs: Any) -> str:
    """
    Romanian icon component (SVG-based)

    Usage:
        {% icon "user" size="lg" %}
        {% icon "invoice" css_class="text-primary" %}

    Args:
        name: Icon name from Romanian icon library
        size: xs|sm|md|lg|xl
        css_class: Additional CSS classes
    """

    # Icon size mapping
    size_classes = {
        "xs": "w-3 h-3",
        "sm": "w-4 h-4",
        "md": "w-5 h-5",
        "lg": "w-6 h-6",
        "xl": "w-8 h-8",
    }

    # Validate and sanitize inputs to prevent XSS
    # Sanitize icon name - only allow alphanumeric and hyphens
    if not re.match(r"^[a-zA-Z0-9\-_]+$", name):
        name = "default"  # Fallback to safe default

    # Build CSS classes with escaped input
    classes = f"inline-block {size_classes.get(size, size_classes['md'])}"
    if css_class:
        # Let format_html escape; avoid pre-escaping to prevent double-escape
        classes += f" {css_class}"

    # 🔒 Security: Use format_html instead of f-strings to prevent XSS
    # All inputs are validated and classes built from known sets; name was sanitized.
    return format_html('<svg class="{}" data-icon="{}"><use href="#icon-{}"></use></svg>', classes, name, name)


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
