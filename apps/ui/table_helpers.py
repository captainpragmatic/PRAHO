"""
===============================================================================
📊 DATA TABLE HELPERS - PRAHO Platform
===============================================================================
Helper functions to convert data into standardized enhanced table format.
These helpers transform model data into the structure expected by our 
table_enhanced component for consistent UI across the platform.
===============================================================================
"""

from typing import Any

from django.urls import reverse
from django.utils.translation import gettext as _

"""
Table helper functions for converting model data to component format.
"""



def prepare_billing_table_data(documents: list[Any], user: Any) -> dict[str, list[dict[str, Any]]]:
    """
    Prepare billing document data for the enhanced table component.
    
    Args:
        documents: List of document dictionaries from billing views
        user: Current user (for permission checks)
        
    Returns:
        Dictionary with 'columns' and 'rows' keys for table_enhanced component
    """
    columns = [
        {"header": _("Document"), "width": "w-1/4"},
        {"header": _("Customer"), "width": "w-1/4"}, 
        {"header": _("Amount"), "width": "w-1/6"},
        {"header": _("Status"), "width": "w-1/6"},
        {"header": _("Date"), "width": "w-1/6"},
    ]
    
    rows = []
    for doc in documents:
        # Handle both dictionary and model object formats
        if isinstance(doc, dict):
            doc_number = doc['number']
            doc_type = doc['type']
            doc_id = doc['id']
            customer = doc['customer']
            total_amount = doc['total']
            created_at = doc['created_at']
            status = doc['status']
        else:
            # Legacy model object support
            doc_number = doc.number
            doc_type = getattr(doc, 'document_type', 'invoice')
            doc_id = doc.pk
            customer = doc.customer
            total_amount = doc.total_amount
            created_at = doc.created_at
            status = doc.status
        
        # Document cell with number and type info
        document_cell = {
            "content": f"<div class='text-white font-medium'>{doc_number}</div>"
                      f"<div class='text-slate-400 text-sm'>{doc_type.title()}</div>",
            "url": reverse('billing:invoice_detail', args=[doc_id]) if doc_type == 'invoice' else reverse('billing:proforma_detail', args=[doc_id])
        }
        
        # Customer cell
        customer_cell = {
            "content": f"<div class='text-white'>{customer.get_display_name()}</div>"
                      f"<div class='text-slate-400 text-sm'>{getattr(customer, 'tax_profile', None) and customer.tax_profile.cui or 'N/A'}</div>"
        }
        
        # Amount cell
        amount_cell = {
            "content": f"<div class='text-white font-medium'>{total_amount:.2f} RON</div>"
        }
        
        # Status badge cell
        status_badge = {
            "draft": {"text": "Draft", "variant": "secondary", "icon": "📝"},
            "sent": {"text": "Sent", "variant": "warning", "icon": "📤"},
            "paid": {"text": "Paid", "variant": "success", "icon": "✅"},
            "overdue": {"text": "Overdue", "variant": "danger", "icon": "⚠️"},
            "cancelled": {"text": "Cancelled", "variant": "secondary", "icon": "❌"},
            "valid": {"text": "Valid", "variant": "success", "icon": "✅"},
            "expired": {"text": "Expired", "variant": "danger", "icon": "❌"},
        }.get(status, {"text": status.title(), "variant": "default", "icon": "🔍"})
        
        status_cell = {
            "component": {
                "type": "badge",
                "text": status_badge["text"],
                "variant": status_badge["variant"],
                "icon": status_badge["icon"]
            }
        }
        
        # Date cell
        date_cell = {
            "content": f"<div class='text-white'>{created_at.strftime('%d.%m.%Y')}</div>"
                      f"<div class='text-slate-400 text-sm'>{created_at.strftime('%H:%M')}</div>"
        }
        
        rows.append({
            "cells": [document_cell, customer_cell, amount_cell, status_cell, date_cell],
            "url": document_cell["url"]  # Row click URL
        })
    
    return {"columns": columns, "rows": rows}


def _get_status_badge_text(document: dict[str, Any]) -> str:
    """Get status badge text for document."""
    if document['type'] == 'proforma':
        return '❌ Expired' if document['status'] == 'expired' else '⏳ Valid'
    else:
        status_map = {
            'paid': '✅ Paid',
            'overdue': '❌ Overdue', 
            'sent': '📧 Sent',
            'pending': '⏳ Pending',
            'cancelled': '❌ Cancelled'
        }
        return status_map.get(document['status'], '📝 Draft')


def _get_status_badge_variant(document: dict[str, Any]) -> str:
    """Get status badge variant for document."""
    if document['type'] == 'proforma':
        return 'danger' if document['status'] == 'expired' else 'success'
    else:
        variant_map = {
            'paid': 'success',
            'overdue': 'danger',
            'sent': 'primary', 
            'pending': 'warning',
            'cancelled': 'danger'
        }
        return variant_map.get(document['status'], 'secondary')


def prepare_orders_table_data(orders_page: Any, user: Any) -> dict[str, Any]:
    """
    Convert orders into enhanced table format.
    
    Args:
        orders_page: Paginated orders
        user: Current user for permission checks
        
    Returns:
        Dictionary with columns and rows for table_enhanced component
    """
    # Define columns for orders
    columns = [
        {'label': _('Order #'), 'width': 'w-32', 'align': 'left', 'sortable': True},
        {'label': _('Customer'), 'width': 'w-48', 'align': 'left', 'sortable': True},
        {'label': _('Products'), 'width': 'w-40', 'align': 'left', 'sortable': False},
        {'label': _('Total'), 'width': 'w-24', 'align': 'right', 'sortable': True},
        {'label': _('Status'), 'width': 'w-28', 'align': 'center', 'sortable': False},
        {'label': _('Date'), 'width': 'w-24', 'align': 'center', 'sortable': True}
    ]
    
    # Convert orders to rows
    rows = []
    for order in orders_page.object_list:
        detail_url = reverse('orders:order_detail', args=[order.id])
        
        # Build cells for order
        cells = [
            {'text': order.order_number, 'font_class': 'font-mono font-medium', 'text_color': 'text-white'},
            {'text': str(order.customer), 'truncate': True, 'title': str(order.customer)},
            {'text': f"{order.items.count()} items", 'text_color': 'text-slate-300'},
            {'text': f"€{order.total:.2f}", 'align': 'right', 'font_class': 'font-mono', 'text_color': 'text-white'},
            {'component': 'badge', 'text': order.get_status_display(), 'variant': _get_order_status_variant(order.status)},
            {'text': order.created_at.strftime('%d.%m.%Y'), 'font_class': 'font-mono', 'text_color': 'text-slate-300'}
        ]
        
        actions = [{'component': 'button', 'text': '👁️', 'variant': 'secondary', 'size': 'xs', 'href': detail_url, 'class': 'px-2'}]
        
        rows.append({
            'clickable': True,
            'click_url': detail_url,
            'cells': cells,
            'actions': actions
        })
    
    return {'columns': columns, 'rows': rows}


def _get_order_status_variant(status: str) -> str:
    """Get status badge variant for order."""
    variant_map = {
        'pending': 'warning',
        'processing': 'primary',
        'completed': 'success',
        'cancelled': 'danger',
        'refunded': 'secondary'
    }
    return variant_map.get(status, 'secondary')


# Add more helper functions for other data types as needed:
# - prepare_tickets_table_data()
# - prepare_customers_table_data() 
# - prepare_services_table_data()
# - prepare_audit_table_data()
