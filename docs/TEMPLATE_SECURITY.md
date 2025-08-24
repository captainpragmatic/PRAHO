# Template Security Guidelines - PRAHO Platform

## 🔒 XSS Prevention in Django Templates

### ⚠️ **SECURITY WARNING**: Use of `|safe` Filter

The `|safe` filter bypasses Django's automatic HTML escaping and can lead to XSS vulnerabilities.

### ✅ **SECURE PATTERNS**

#### **1. Default Auto-Escaping (RECOMMENDED)**
```html
<!-- ✅ SECURE: Django automatically escapes HTML -->
<div>{{ user_message }}</div>

<!-- ❌ DANGEROUS: Could allow XSS -->
<div>{{ user_message|safe }}</div>
```

#### **2. Controlled HTML Content**
For legitimate HTML content (like buttons, forms), use structured approaches:

```html
<!-- ✅ SECURE: Template composition -->
{% if cell.type == 'button' %}
  <button class="{{ cell.class }}">{{ cell.text }}</button>
{% elif cell.type == 'link' %}
  <a href="{{ cell.url }}">{{ cell.text }}</a>
{% else %}
  {{ cell.value }}
{% endif %}

<!-- ❌ AVOID: Direct HTML injection -->
{{ cell.html|safe }}
```

#### **3. Escape and Mark Safe in Python**
```python
from django.utils.html import format_html
from django.utils.safestring import mark_safe

# ✅ SECURE: Controlled HTML generation
def create_button_html(text, url):
    return format_html(
        '<a href="{}" class="btn btn-primary">{}</a>',
        url, text
    )

# ❌ DANGEROUS: String concatenation
def create_button_html_bad(text, url):
    return mark_safe(f'<a href="{url}">{text}</a>')
```

### 🛡️ **CURRENT COMPONENT SECURITY STATUS**

| Component | Status | Risk Level | Action |
|-----------|--------|------------|---------|
| `alert.html` | ✅ FIXED | Low | Removed `|safe` from message |
| `modal.html` | ⚠️ REVIEW | Medium | Legitimate HTML content use |
| `table.html` | ⚠️ REVIEW | Medium | Structured for HTML cells |
| `button.html` | ✅ SECURE | Low | Internal component attributes |

### 🔧 **RECOMMENDED IMPROVEMENTS**

1. **Input Validation**: Validate all user input at the view level
2. **Content Security Policy**: Use CSP headers to prevent inline scripts
3. **Template Reviews**: Regular security audits of template changes
4. **Alternative Patterns**: Use template composition over `|safe`

### 📋 **Security Checklist for Templates**

- [ ] Remove unnecessary `|safe` filters
- [ ] Validate all user-generated content
- [ ] Use `format_html()` for dynamic HTML
- [ ] Implement CSP headers
- [ ] Regular template security reviews
- [ ] Escape user input in JavaScript contexts

### 🚨 **Emergency Response**

If XSS vulnerability is suspected:
1. Remove `|safe` filter immediately
2. Review all user input paths
3. Check recent template changes
4. Audit logs for suspicious activity
5. Update security documentation
