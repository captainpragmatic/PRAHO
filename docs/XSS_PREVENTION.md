# Template Security Guidelines - PRAHO Platform

## 🔒 XSS Prevention in Templates

### ❌ **DANGEROUS - Do Not Use**

```html
<!-- NEVER USE |safe with user input -->
{{ user_message|safe }}  <!-- XSS VULNERABILITY -->
{{ request.GET.param|safe }}  <!-- XSS VULNERABILITY -->
```

### ✅ **SECURE - Recommended Patterns**

#### **1. Use Automatic Escaping (Default)**
```html
<!-- Django automatically escapes by default -->
{{ user_message }}  <!-- Safe - HTML is escaped -->
{{ form.field.value }}  <!-- Safe - form data escaped -->
```

#### **2. Use Security Template Tags**
```html
{% load security_tags %}

<!-- For messages with basic formatting -->
{{ message|safe_message }}  <!-- Allows only <b>, <i>, <strong>, <em>, <u> -->

<!-- For complete safety -->
{{ user_content|escape_message }}  <!-- Escapes all HTML -->

<!-- For alerts -->
{% secure_alert "Your message here" "success" %}
```

#### **3. Use format_html for Dynamic Content**
```python
# In views.py
from django.utils.html import format_html

message = format_html(
    'Welcome <strong>{}</strong>! You have {} messages.',
    user.first_name,  # Automatically escaped
    message_count
)
```

### 🛡️ **Component Security**

#### **Alert Component**
```html
<!-- BEFORE (vulnerable) -->
<div>{{ message|safe }}</div>

<!-- AFTER (secure) -->
<div>{{ message|escape }}</div>
<!-- OR -->
{% load security_tags %}
{% secure_alert message "info" %}
```

#### **Modal Component**
```html
<!-- For static content only -->
{% include 'components/modal.html' with content="<p>Safe static content</p>" %}

<!-- For dynamic content -->
{% include 'components/modal.html' with content=escaped_content %}
```

### 📋 **Security Checklist**

- [ ] No `|safe` filter with user input
- [ ] Use `{% load security_tags %}` for safe HTML
- [ ] Validate all user input before template rendering
- [ ] Use `format_html()` for dynamic HTML generation
- [ ] Test with malicious input: `<script>alert('XSS')</script>`
- [ ] Review CSP headers for XSS protection

### 🧪 **Testing XSS Protection**

Test these inputs in your templates to ensure they're safely escaped:

```html
<!-- Test inputs -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
<svg onload=alert('XSS')>
```

Expected result: All should render as plain text, not execute.

### 🚨 **Common XSS Vulnerabilities**

1. **User messages/comments**: Always escape
2. **Search queries**: Never use |safe
3. **URL parameters**: Validate and escape
4. **File names**: Can contain malicious content
5. **User profiles**: Names, descriptions need escaping

### 🔧 **CSP Headers**

The platform includes these CSP protections:

```
Content-Security-Policy: 
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline' fonts.googleapis.com;
  font-src 'self' fonts.gstatic.com;
  img-src 'self' data: https:;
```

This prevents inline scripts and most XSS attacks.
