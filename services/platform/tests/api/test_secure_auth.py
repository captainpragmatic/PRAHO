import ast
import json
import time
from pathlib import Path
from unittest.mock import patch

from django.http import HttpRequest
from django.test import SimpleTestCase, TestCase
from rest_framework import status
from rest_framework.response import Response

from apps.api.secure_auth import (
    require_user_authentication,
    validate_hmac_authenticated_request,
)
from apps.api.services import views as svc_views


class RequireUserAuthenticationLoggingTests(SimpleTestCase):
    """require_user_authentication must emit decorator-level entry,
    success, and failure logs at the same severity levels as the sibling
    require_customer_authentication decorator. Without these logs, an
    auth-failure storm on session-validation endpoints leaves no trace
    in the logger=apps.api.secure_auth log stream and operators can't
    correlate it to a specific decorator path (PR #164 review M3).
    """

    @staticmethod
    def _decorated_view():
        @require_user_authentication
        def view(request, user):
            return Response({"ok": True})
        return view

    @patch("apps.api.secure_auth.get_authenticated_user")
    def test_logs_failure_at_warning(self, mock_get_user) -> None:
        """When get_authenticated_user returns an error_response, the
        decorator must emit a WARNING with the request path so failure
        spikes are visible in log aggregators."""
        mock_get_user.return_value = (None, Response({"error": "no auth"}, status=status.HTTP_401_UNAUTHORIZED))
        view = self._decorated_view()
        request = HttpRequest()
        request.path = "/api/users/session/validate/"

        with self.assertLogs("apps.api.secure_auth", level="WARNING") as ctx:
            response = view(request)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertTrue(
            any("require_user_authentication" in msg or "User auth failed" in msg
                for msg in ctx.output),
            msg=f"Expected a WARNING about user auth failure; got: {ctx.output}",
        )

    @patch("apps.api.secure_auth.get_authenticated_user")
    def test_logs_entry_and_success_at_debug(self, mock_get_user) -> None:
        """When auth succeeds, the decorator must emit DEBUG entry and
        success logs (silent at INFO+/WARNING+ to avoid log noise per
        the PR #164 perf optimization, but visible at DEBUG for tracing)."""
        fake_user = type("U", (), {"email": "test@example.com"})()
        mock_get_user.return_value = (fake_user, None)
        view = self._decorated_view()
        request = HttpRequest()
        request.path = "/api/users/session/validate/"

        with self.assertLogs("apps.api.secure_auth", level="DEBUG") as ctx:
            response = view(request)

        self.assertEqual(response.status_code, 200)
        # Entry log fires regardless of outcome.
        self.assertTrue(
            any("require_user_authentication" in msg for msg in ctx.output),
            msg=f"Expected a DEBUG entry log; got: {ctx.output}",
        )


class SecureAuthValidationTests(TestCase):
    def _make_request(self, body_dict: dict) -> HttpRequest:
        req = HttpRequest()
        req.method = "POST"
        body = json.dumps(body_dict).encode()
        req._body = body
        req.META["CONTENT_TYPE"] = "application/json"
        # Simulate that middleware already authenticated HMAC
        req._portal_authenticated = True
        return req

    def test_missing_user_id_is_rejected(self):
        request = self._make_request(
            {
                "customer_id": 123,
                "timestamp": time.time(),
            }
        )
        data, error = validate_hmac_authenticated_request(request)
        self.assertIsNone(data)
        self.assertIsNotNone(error)
        self.assertEqual(error.status_code, 400)

    def test_valid_body_is_accepted(self):
        request = self._make_request(
            {
                "customer_id": 123,
                "user_id": 42,
                "timestamp": time.time(),
            }
        )
        data, error = validate_hmac_authenticated_request(request)
        self.assertIsNone(error)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["user_id"], 42)
        self.assertEqual(data["customer_id"], 123)


class RequireCustomerAuthParameterOrderTests(SimpleTestCase):
    """Ensure views decorated with @require_customer_authentication have
    ``customer`` as the first parameter after ``request``.

    The decorator calls ``view_func(request, customer, *args, **kwargs)``,
    so any URL-captured params (like ``service_id``) must come *after*
    ``customer`` in the function signature to avoid 'got multiple values'
    TypeError at runtime.

    We parse the source AST because the decorator chain
    (@api_view → @permission_classes → @require_customer_authentication)
    does not preserve __wrapped__, making runtime introspection unreliable.
    """

    def _find_decorated_funcs(self, source_path: Path) -> list[tuple[str, list[str]]]:
        """Return [(func_name, [param_names])] for functions decorated with
        @require_customer_authentication in the given file."""
        tree = ast.parse(source_path.read_text())
        results = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            decorator_names = [d.id if isinstance(d, ast.Name) else getattr(d, "attr", "") for d in node.decorator_list]
            if "require_customer_authentication" in decorator_names:
                params = [arg.arg for arg in node.args.args]
                results.append((node.name, params))
        return results

    def test_decorated_views_have_customer_second(self) -> None:
        source_path = Path(svc_views.__file__)
        decorated = self._find_decorated_funcs(source_path)
        self.assertGreater(len(decorated), 0, "No @require_customer_authentication views found")

        for func_name, params in decorated:
            self.assertGreaterEqual(len(params), 2, f"{func_name} should have at least (request, customer)")
            self.assertEqual(
                params[1],
                "customer",
                f"{func_name}: second param should be 'customer', got '{params[1]}'. "
                f"The @require_customer_authentication decorator passes customer as the "
                f"first positional arg after request.",
            )
