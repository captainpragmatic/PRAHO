# Template and CSP Security Guide - PRAHO Platform

Developer guide for writing secure Django templates, CSP compliance, and HTMX security patterns.

## XSS Prevention in Django Templates

### SECURITY WARNING: Use of `|safe` Filter

The `|safe` filter bypasses Django's automatic HTML escaping and can lead to XSS vulnerabilities.

### Secure Patterns

#### 1. Default Auto-Escaping (RECOMMENDED)
```html
<!-- ✅ SECURE: Django automatically escapes HTML -->
<div>{{ user_message }}</div>

<!-- ❌ DANGEROUS: Could allow XSS -->
<div>{{ user_message|safe }}</div>
```

#### 2. Controlled HTML Content
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

#### 3. Escape and Mark Safe in Python
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

### Component Security Status

| Component | Status | Risk Level | Action |
|-----------|--------|------------|---------|
| `alert.html` | FIXED | Low | Removed `|safe` from message |
| `modal.html` | ACCEPTED | Low | Content controlled at view layer via dataclass objects |
| `table.html` | ACCEPTED | Low | Content controlled at view layer via dataclass objects |
| `button.html` | SECURE | Low | Internal component attributes |

### Recommended Improvements

1. **Input Validation**: Validate all user input at the view level
2. **Content Security Policy**: Use CSP headers to prevent inline scripts
3. **Template Reviews**: Regular security audits of template changes
4. **Alternative Patterns**: Use template composition over `|safe`

### Security Checklist for Templates

- [ ] Remove unnecessary `|safe` filters
- [ ] Validate all user-generated content
- [ ] Use `format_html()` for dynamic HTML
- [ ] Implement CSP headers
- [ ] Regular template security reviews
- [ ] Escape user input in JavaScript contexts

### Emergency Response

If XSS vulnerability is suspected:
1. Remove `|safe` filter immediately
2. Review all user input paths
3. Check recent template changes
4. Audit logs for suspicious activity
5. Update security documentation

---

## Content Security Policy (CSP)

### Current CSP Directives

Source: `apps/common/middleware.py` — `SecurityHeadersMiddleware`

```
default-src 'self';
style-src 'self' 'unsafe-inline' fonts.googleapis.com cdn.tailwindcss.com;
font-src 'self' fonts.gstatic.com;
script-src 'self' 'unsafe-inline' 'unsafe-eval' unpkg.com cdn.tailwindcss.com;
img-src 'self' data: https:;
connect-src 'self';
object-src 'none';
base-uri 'self';
form-action 'self';
```

### Why `unsafe-inline` and `unsafe-eval`

Tailwind CSS CDN (`cdn.tailwindcss.com`) injects styles dynamically and requires `unsafe-inline` in `style-src`. Alpine.js and HTMX inline event handlers require `unsafe-inline` in `script-src`. Tailwind's JIT compiler uses `unsafe-eval` for runtime style generation.

**Production hardening path**: Replace CDN Tailwind with a pre-built CSS bundle (already done via `make build-css`), then remove `unsafe-inline`/`unsafe-eval` and implement CSP nonces. This is tracked as a gap in the [Security Compliance Assessment](../security/SECURITY_COMPLIANCE_ASSESSMENT.md).

> For full header configuration details, see [Security Configuration Guide](../security/SECURITY_CONFIGURATION.md#4-security-headers).

---

## HTMX CSRF Protection

All HTMX `POST` endpoints require CSRF tokens. Use `hx-headers` to include the token:

```html
<button hx-post="{% url 'app:action' %}" hx-headers='{"X-CSRFToken": "{{ csrf_token }}"}' hx-swap="none" hx-indicator="#spinner">
    Perform Action
</button>
```

For forms using `hx-post`, you can also use the standard `{% csrf_token %}` hidden input if the form is submitted as `application/x-www-form-urlencoded`.

> For complete HTMX patterns (partials, E2E testing, triggers), see the [HTMX Guidelines in CLAUDE.md](../../CLAUDE.md#htmx-guidelines).

---

## Content Sanitization

When using `|safe` in templates, all HTML content **must** be constructed safely at the view layer:

- Use `format_html()` for any dynamic HTML generation
- Use dataclass objects with pre-defined HTML structure for table cells and modals
- Never pass user input directly to `|safe` — always escape or construct via `format_html()`

```python
from django.utils.html import format_html

# SAFE: format_html escapes parameters
cell_html = format_html('<a href="{}">{}</a>', url, label)

# DANGEROUS: never do this
cell_html = f'<a href="{url}">{label}</a>'
```

> For Django template formatting rules (comparison operators, filter arguments, HTMX attributes), see the [Django Template Pitfalls in CLAUDE.md](../../CLAUDE.md#django-template-pitfalls).

---

## Related Documents

- [Security Configuration Guide](../security/SECURITY_CONFIGURATION.md) — full CSP header and security settings
- [Security Compliance Assessment](../security/SECURITY_COMPLIANCE_ASSESSMENT.md) — CSP gap analysis
- [CLAUDE.md HTMX Guidelines](../../CLAUDE.md#htmx-guidelines) — HTMX development patterns
- [CLAUDE.md Django Template Pitfalls](../../CLAUDE.md#django-template-pitfalls) — template formatting rules

---

**Last Updated**: March 2026
**Review Schedule**: Quarterly
