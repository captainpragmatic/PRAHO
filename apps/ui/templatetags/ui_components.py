"""
PRAHO PLATFORM - UI Components Template Tags
===============================================================================
HTMX-powered reusable components for Romanian hosting provider interface
"""

from django import template
from django.utils.safestring import mark_safe
from django.urls import reverse
from typing import Dict, Any, Optional

register = template.Library()


@register.inclusion_tag('components/button.html')
def button(
    text: str,
    *,
    variant: str = 'primary',
    size: str = 'md',
    href: Optional[str] = None,
    type: str = 'button',
    hx_get: Optional[str] = None,
    hx_post: Optional[str] = None,
    hx_put: Optional[str] = None,
    hx_patch: Optional[str] = None,
    hx_delete: Optional[str] = None,
    hx_target: Optional[str] = None,
    hx_swap: Optional[str] = None,
    hx_trigger: Optional[str] = None,
    hx_confirm: Optional[str] = None,
    hx_indicator: Optional[str] = None,
    hx_push_url: Optional[str] = None,
    hx_select: Optional[str] = None,
    hx_boost: bool = False,
    icon: Optional[str] = None,
    icon_right: bool = False,
    disabled: bool = False,
    class_: str = '',
    attrs: str = '',
    **kwargs
) -> Dict[str, Any]:
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
    
    return {
        'text': text,
        'variant': variant,
        'size': size,
        'href': href,
        'type': type,
        'hx_get': hx_get,
        'hx_post': hx_post,
        'hx_put': hx_put,
        'hx_patch': hx_patch,
        'hx_delete': hx_delete,
        'hx_target': hx_target,
        'hx_swap': hx_swap,
        'hx_trigger': hx_trigger,
        'hx_confirm': hx_confirm,
        'hx_indicator': hx_indicator,
        'hx_push_url': hx_push_url,
        'hx_select': hx_select,
        'hx_boost': hx_boost,
        'icon': icon,
        'icon_right': icon_right,
        'disabled': disabled,
        'class': class_,
        'attrs': attrs,
    }


@register.inclusion_tag('components/input.html')
def input_field(
    name: str,
    *,
    input_type: str = 'text',
    value: Optional[str] = None,
    label: Optional[str] = None,
    placeholder: Optional[str] = None,
    required: bool = False,
    disabled: bool = False,
    readonly: bool = False,
    error: Optional[str] = None,
    help_text: Optional[str] = None,
    icon_left: Optional[str] = None,
    icon_right: Optional[str] = None,
    css_class: str = '',
    html_id: Optional[str] = None,
    hx_get: Optional[str] = None,
    hx_post: Optional[str] = None,
    hx_trigger: Optional[str] = None,
    hx_target: Optional[str] = None,
    hx_swap: Optional[str] = None,
    options: Optional[list] = None,
    romanian_validation: bool = True,
    **kwargs
) -> Dict[str, Any]:
    """
    Romanian hosting provider input component with HTMX support
    
    Usage:
        {% input_field "email" label="Email" input_type="email" required=True %}
        {% input_field "search" label="Căutare client" icon_left="search" hx_get="/customers/search/" hx_trigger="keyup changed delay:300ms" %}
    """
    
    # Auto-generate ID if not provided
    if not html_id:
        html_id = f"input-{name}"
    
    return {
        'name': name,
        'input_type': input_type,
        'value': value,
        'label': label,
        'placeholder': placeholder,
        'required': required,
        'disabled': disabled,
        'readonly': readonly,
        'error': error,
        'help_text': help_text,
        'icon_left': icon_left,
        'icon_right': icon_right,
        'css_class': css_class,
        'html_id': html_id,
        'hx_get': hx_get,
        'hx_post': hx_post,
        'hx_trigger': hx_trigger,
        'hx_target': hx_target,
        'hx_swap': hx_swap,
        'options': options,
        'romanian_validation': romanian_validation,
        'has_error': bool(error),
        **kwargs
    }


@register.inclusion_tag('components/checkbox.html')
def checkbox_field(
    name: str,
    *,
    label: Optional[str] = None,
    value: Optional[str] = None,
    checked: bool = False,
    required: bool = False,
    disabled: bool = False,
    error: Optional[str] = None,
    help_text: Optional[str] = None,
    variant: str = 'primary',
    css_class: str = '',
    container_class: str = '',
    html_id: Optional[str] = None,
    hx_get: Optional[str] = None,
    hx_post: Optional[str] = None,
    hx_trigger: Optional[str] = None,
    hx_target: Optional[str] = None,
    hx_swap: Optional[str] = None,
    data_attrs: Optional[dict] = None,
    **kwargs
) -> Dict[str, Any]:
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
    
    # Auto-generate ID if not provided
    if not html_id:
        html_id = f"checkbox-{name}"
    
    # Default value for checkboxes
    if not value:
        value = "on"
    
    return {
        'name': name,
        'label': label,
        'value': value,
        'checked': checked,
        'required': required,
        'disabled': disabled,
        'error': error,
        'help_text': help_text,
        'variant': variant,
        'css_class': css_class,
        'container_class': container_class,
        'html_id': html_id,
        'hx_get': hx_get,
        'hx_post': hx_post,
        'hx_trigger': hx_trigger,
        'hx_target': hx_target,
        'hx_swap': hx_swap,
        'data_attrs': data_attrs or {},
        **kwargs
    }


@register.inclusion_tag('components/alert.html')
def alert(
    message: str,
    *,
    variant: str = 'info',
    title: Optional[str] = None,
    dismissible: bool = False,
    show_icon: bool = True,
    css_class: str = '',
    html_id: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Romanian hosting provider alert component
    
    Usage:
        {% alert "Factura a fost emisă cu succes!" variant="success" dismissible=True %}
        {% alert "Clientul nu are un VAT ID valid" variant="warning" title="Atenție" %}
    """
    return {
        'message': message,
        'variant': variant,
        'title': title,
        'dismissible': dismissible,
        'show_icon': show_icon,
        'css_class': css_class,
        'html_id': html_id,
        **kwargs
    }


@register.inclusion_tag('components/modal.html')
def modal(
    modal_id: str,
    title: str,
    *,
    size: str = 'md',
    closeable: bool = True,
    show_footer: bool = True,
    content: Optional[str] = None,
    css_class: str = '',
    html_id: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
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
    return {
        'modal_id': modal_id,
        'title': title,
        'size': size,
        'closeable': closeable,
        'show_footer': show_footer,
        'content': content,
        'css_class': css_class,
        'html_id': html_id,
        **kwargs
    }




@register.inclusion_tag('components/table.html')
def data_table(
    headers: list,
    rows: list,
    *,
    sortable: bool = True,
    searchable: bool = True,
    pagination: bool = True,
    actions: Optional[list] = None,
    css_class: str = '',
    empty_message: str = 'Nu există date disponibile.',
    **kwargs
) -> Dict[str, Any]:
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
    return {
        'headers': headers,
        'rows': rows,
        'sortable': sortable,
        'searchable': searchable,
        'pagination': pagination,
        'actions': actions or [],
        'css_class': css_class,
        'empty_message': empty_message,
        'has_data': bool(rows),
    }


@register.inclusion_tag('components/toast.html')
def toast(
    message: str,
    *,
    variant: str = 'info',
    dismissible: bool = True,
    auto_dismiss: int = 5000,
    toast_id: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
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
        'message': message,
        'variant': variant,
        'dismissible': dismissible,
        'auto_dismiss': auto_dismiss,
        'toast_id': toast_id,
    }


@register.inclusion_tag('components/card.html')
def card(
    title: Optional[str] = None,
    *,
    subtitle: Optional[str] = None,
    footer: Optional[str] = None,
    css_class: str = '',
    actions: Optional[list] = None,
    **kwargs
) -> Dict[str, Any]:
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
        'title': title,
        'subtitle': subtitle,
        'footer': footer,
        'css_class': css_class,
        'actions': actions or [],
        'has_header': bool(title or subtitle or actions),
        'has_footer': bool(footer),
    }


@register.inclusion_tag('components/breadcrumb.html')
def breadcrumb(
    items: list,
    *,
    css_class: str = '',
    separator: str = '/',
    **kwargs
) -> Dict[str, Any]:
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
        'items': items,
        'css_class': css_class,
        'separator': separator,
    }


@register.simple_tag
def icon(
    name: str,
    *,
    size: str = 'md',
    css_class: str = '',
    **kwargs
) -> str:
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
        'xs': 'w-3 h-3',
        'sm': 'w-4 h-4', 
        'md': 'w-5 h-5',
        'lg': 'w-6 h-6',
        'xl': 'w-8 h-8',
    }
    
    # Validate and sanitize inputs to prevent XSS
    from django.utils.html import escape
    import re
    
    # Sanitize icon name - only allow alphanumeric and hyphens
    if not re.match(r'^[a-zA-Z0-9\-_]+$', name):
        name = 'default'  # Fallback to safe default
    
    # Build CSS classes with escaped input
    classes = f"inline-block {size_classes.get(size, size_classes['md'])}"
    if css_class:
        classes += f" {escape(css_class)}"
    
    # Escape all inputs before rendering
    safe_name = escape(name)
    safe_classes = escape(classes)
    
    # For now, return a placeholder - will be replaced with actual SVG icons
    return mark_safe(f'<svg class="{safe_classes}" data-icon="{safe_name}"><use href="#icon-{safe_name}"></use></svg>')  # nosec B308 B703 - All inputs are validated and escaped


@register.simple_tag(takes_context=True)
def active_link(context, url_name: str, css_class: str = 'active') -> str:
    """
    Add CSS class if current URL matches the given URL name
    
    Usage:
        <a href="{% url 'customers:list' %}" class="nav-link {% active_link 'customers:list' %}">
    
    Args:
        url_name: Django URL name to check
        css_class: CSS class to add if active
    """
    request = context.get('request')
    if request and request.resolver_match:
        current_url_name = request.resolver_match.url_name
        current_namespace = request.resolver_match.namespace
        
        # Build full URL name with namespace
        full_current = f"{current_namespace}:{current_url_name}" if current_namespace else current_url_name
        
        if full_current == url_name:
            return css_class
    
    return ''


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
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = bytes_value
    unit_index = 0
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.1f} {units[unit_index]}"


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
    formatted = f"{percentage:.{decimals}f}".replace('.', ',')
    return f"{formatted}%"
