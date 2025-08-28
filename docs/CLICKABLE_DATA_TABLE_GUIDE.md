# 📊 Enhanced Table Component Guide

## Overview

The `table_enhanced` component is a **standardized, reusable table component** for PRAHO Platform that provides:

- ✅ **Clickable rows** with navigation
- ✅ **Fixed column widths** for consistency  
- ✅ **Badge and button integration**
- ✅ **HTMX pagination support**
- ✅ **Romanian business theming**
- ✅ **Responsive design**

## Basic Usage

### 1. Template Tag
```html
{% load ui_components %}

{% table_enhanced 
   columns=table_columns 
   rows=table_rows 
   page_obj=page_obj
   pagination_enabled=True
   show_actions=True %}
```

### 2. Column Definition
```python
columns = [
    {
        'label': _('Document Type'),
        'width': 'w-28',           # Tailwind width class
        'align': 'center',         # left|center|right
        'sortable': True           # Enable sorting button
    },
    {
        'label': _('Number'),
        'width': 'w-32',
        'align': 'left', 
        'sortable': True
    }
]
```

### 3. Row Definition
```python
rows = [
    {
        'clickable': True,
        'click_url': '/billing/invoice/123/',  # Direct URL navigation
        'cells': [
            {
                'component': 'badge',      # Use badge component
                'text': '🧾 Invoice',
                'variant': 'success',
                'align': 'center',
                'no_wrap': True
            },
            {
                'text': 'INV-2024-001',   # Plain text cell
                'font_class': 'font-mono',
                'text_color': 'text-white',
                'truncate': True,
                'title': 'Full invoice number'  # Tooltip
            }
        ],
        'actions': [
            {
                'component': 'button',
                'text': '👁️',
                'variant': 'secondary',
                'size': 'xs',
                'href': '/view/123/',
                'class': 'px-2'
            }
        ]
    }
]
```

## Cell Types

### Badge Cell
```python
{
    'component': 'badge',
    'text': '✅ Paid',
    'variant': 'success',      # primary|secondary|success|warning|danger
    'align': 'center'
}
```

### Button Cell
```python
{
    'component': 'button',
    'text': 'View',
    'variant': 'primary',
    'size': 'xs',             # xs|sm|md|lg
    'href': '/view/123/'
}
```

### Text Cell
```python
{
    'text': 'Customer Name',
    'align': 'left',          # left|center|right
    'truncate': True,         # Add ellipsis for long text
    'title': 'Full text',     # Tooltip on hover
    'font_class': 'font-mono', # Additional font classes
    'text_color': 'text-white', # Text color class
    'no_wrap': True           # Prevent text wrapping
}
```

## Navigation Options

### Direct URL Navigation
```python
{
    'clickable': True,
    'click_url': '/billing/invoice/123/'
}
```

### JavaScript Navigation  
```python
{
    'clickable': True,
    'click_js': 'navigateToDocument("invoice", "123")'
}
```

## Helper Functions

Use `apps.ui.table_helpers` to convert your data:

```python
from apps.ui.table_helpers import prepare_billing_table_data

# In your view
table_data = prepare_billing_table_data(documents_page, request.user)

context = {
    'table_data': table_data,
    'documents': documents_page
}
```

## HTMX Integration

```html
```html
<!-- In any template -->
{% table_enhanced columns=table_data.columns rows=table_data.rows %}
```
```

## Column Width Standards

Use consistent Tailwind width classes:

| Content Type | Width Class | Pixels | Use Case |
|--------------|-------------|--------|----------|
| `w-16` | 64px | Icon/Actions | Single icon button |
| `w-24` | 96px | Short Data | Dates, amounts |
| `w-28` | 112px | Badges | Status badges, types |
| `w-32` | 128px | Codes | Document numbers, IDs |
| `w-48` | 192px | Names | Customer names, titles |

## Examples in PRAHO

### Billing Documents
```python
# apps/billing/views.py
table_data = prepare_billing_table_data(documents_page, request.user)
```

### Orders
```python  
# apps/orders/views.py
table_data = prepare_orders_table_data(orders_page, request.user)
```

### Future Implementation
- `prepare_tickets_table_data()`
- `prepare_customers_table_data()`
- `prepare_services_table_data()`
- `prepare_audit_table_data()`

## Benefits

✅ **Consistency**: Same look and behavior across all lists  
✅ **Maintainability**: Single component to update  
✅ **Performance**: Optimized rendering and interactions  
✅ **Accessibility**: Proper ARIA labels and keyboard navigation  
✅ **Mobile-friendly**: Responsive design patterns  
✅ **HTMX Ready**: Built-in pagination and dynamic loading  

## Migration Guide

### Before (Custom Table)
```html
<table class="custom-table">
  <tr onclick="location.href='/view/123/'">
    <td>Manual HTML</td>
  </tr>
</table>
```

### After (Component)
```html
{% table_enhanced columns=cols rows=rows %}
```

This component standardizes our table patterns and makes them reusable across the entire PRAHO platform! 🎯
