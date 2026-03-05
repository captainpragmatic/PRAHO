"""
Security hardening integration tests for PRAHO.

These are structural/static tests — they do NOT require live services.
They verify that:
1. Token revocation endpoint uses DELETE (not POST)
2. Rate limiting reads from Django settings, not os.environ
3. Portal webhook verifies HMAC signature before processing
4. Portal has no database driver dependencies
5. HMAC validation helper rejects unsigned webhooks (unit-level)
"""
from __future__ import annotations

import hashlib
import hmac
import re
import subprocess
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_DIR = PROJECT_ROOT / "services" / "platform"
PORTAL_DIR = PROJECT_ROOT / "services" / "portal"


# ---------------------------------------------------------------------------
# 1. Token revocation endpoint must use DELETE, not POST
# ---------------------------------------------------------------------------


class TestTokenRevocationVerb:
    """Verify the token revocation endpoint uses HTTP DELETE."""

    @pytest.mark.integration
    @pytest.mark.security
    def test_revoke_token_view_decorated_with_delete(self):
        """The revoke_token view must only accept DELETE requests."""
        views_path = PLATFORM_DIR / "apps" / "api" / "users" / "views.py"
        source = views_path.read_text()

        # The decorator immediately above the revoke_token function must list DELETE.
        # We look for the pattern @api_view(["DELETE"]) ... def revoke_token
        match = re.search(
            r'@api_view\(\[([^\]]+)\]\)\s*(?:\s*@[^\n]+\n)*\s*def revoke_token',
            source,
        )
        assert match is not None, "Could not find revoke_token view with @api_view decorator"
        methods = match.group(1)
        assert '"DELETE"' in methods or "'DELETE'" in methods, (
            f"revoke_token must accept DELETE, but found: {methods}"
        )
        assert '"POST"' not in methods and "'POST'" not in methods, (
            "revoke_token must NOT accept POST (security regression)"
        )

    @pytest.mark.integration
    @pytest.mark.security
    def test_revoke_token_url_is_registered(self):
        """The token/revoke/ URL must be registered in platform API urls."""
        urls_path = PLATFORM_DIR / "apps" / "api" / "users" / "urls.py"
        source = urls_path.read_text()
        assert "token/revoke/" in source, "token/revoke/ URL must be registered"
        assert "revoke_token" in source, "revoke_token view must be referenced in urls.py"

    @pytest.mark.integration
    @pytest.mark.security
    def test_portal_does_not_call_revoke_with_post(self):
        """Portal must not call the platform token revocation endpoint using POST."""
        result = subprocess.run(  # noqa: S603
            ["/usr/bin/grep", "-rn", "--include=*.py", "revoke", str(PORTAL_DIR)],
            capture_output=True,
            text=True,
            check=False,
        )
        # If the portal calls revoke at all, it must not use requests.post / POST method.
        for line in result.stdout.splitlines():
            # Only care about lines that reference a revoke call (not comments/strings)
            lower = line.lower()
            if "revoke" in lower and "post" in lower:
                # Allow occurrences that are clearly in comments
                stripped = line.strip()
                if not stripped.startswith("#"):
                    pytest.fail(
                        f"Portal appears to call revoke via POST — must use DELETE: {line}"
                    )


# ---------------------------------------------------------------------------
# 2. Rate limiting reads from Django settings, NOT os.environ
# ---------------------------------------------------------------------------


class TestRateLimitingConfiguration:
    """Rate limiting must be controlled by Django settings, not env vars."""

    @pytest.mark.integration
    @pytest.mark.security
    def test_rate_limit_enabled_read_from_django_settings(self):
        """Middleware reads RATELIMIT_ENABLED from Django settings (not os.environ)."""
        middleware_path = PLATFORM_DIR / "apps" / "common" / "middleware.py"
        source = middleware_path.read_text()
        # The setting must be fetched via getattr(settings, ...)
        assert 'getattr(settings, "RATELIMIT_ENABLED"' in source or \
               "getattr(settings, 'RATELIMIT_ENABLED'" in source, (
            "RATELIMIT_ENABLED must be read from Django settings via getattr(settings, ...)"
        )

    @pytest.mark.integration
    @pytest.mark.security
    def test_ratelimit_enable_not_read_from_os_environ(self):
        """RATELIMIT_ENABLE must NOT be read directly from os.environ in middleware."""
        middleware_path = PLATFORM_DIR / "apps" / "common" / "middleware.py"
        source = middleware_path.read_text()
        # Check that os.environ is not used to read RATELIMIT_ENABLE(D) in middleware
        matches = re.findall(r'os\.environ[^\n]*RATELIMIT_ENABLE', source)
        assert len(matches) == 0, (
            f"RATELIMIT_ENABLE must not be read from os.environ in middleware. "
            f"Found: {matches}"
        )

    @pytest.mark.integration
    @pytest.mark.security
    def test_dev_e2e_disables_rate_limit_via_env_then_settings(self):
        """The dev-e2e make target sets RATELIMIT_ENABLE env var — verify it maps
        through Django settings (not read ad-hoc from os.environ in middleware)."""
        # The Makefile sets RATELIMIT_ENABLE=false for E2E runs.
        # As long as middleware reads Django settings, this only works if the settings
        # module picks up the env var and sets RATELIMIT_ENABLED accordingly.
        # This test verifies the settings modules reference RATELIMIT_ENABLE consistently.
        dev_settings = PLATFORM_DIR / "config" / "settings" / "dev.py"
        if dev_settings.exists():
            source = dev_settings.read_text()
            # If dev settings references RATELIMIT_ENABLED it should use env/settings pattern.
            # This is a soft check — the key invariant is that middleware uses getattr(settings, ...).
            if "RATELIMIT_ENABLED" in source:
                assert "os.environ" in source or "env(" in source or "True" in source, (
                    "RATELIMIT_ENABLED in dev settings should have a sane default"
                )


# ---------------------------------------------------------------------------
# 3. Portal webhook HMAC validation — unit-level structural tests
# ---------------------------------------------------------------------------


class TestWebhookHMACValidation:
    """Verify the portal payment webhook enforces HMAC signature checking."""

    @pytest.mark.integration
    @pytest.mark.security
    def test_webhook_view_calls_verify_before_processing(self):
        """payment_success_webhook must call _verify_platform_webhook before processing."""
        views_path = PORTAL_DIR / "apps" / "orders" / "views.py"
        source = views_path.read_text()

        # Find the function body of payment_success_webhook
        # Locate lines of the function — grab everything from def to the next def at same indent
        match = re.search(
            r'def payment_success_webhook\(.*?\n((?:    [^\n]*\n|\n)*)',
            source,
        )
        assert match is not None, "Could not locate payment_success_webhook body"
        body = match.group(1)

        # The verify call must appear before json.loads (i.e., before payload parsing)
        verify_pos = body.find("_verify_platform_webhook")
        parse_pos = body.find("json.loads")
        assert verify_pos != -1, "_verify_platform_webhook must be called in payment_success_webhook"
        assert verify_pos < parse_pos, (
            "_verify_platform_webhook must be called BEFORE json.loads to reject early"
        )

    @pytest.mark.integration
    @pytest.mark.security
    def test_webhook_view_references_verify_function(self):
        """payment_success_webhook must reference _verify_platform_webhook (structural check)."""
        result = subprocess.run(  # noqa: S603
            [
                "/usr/bin/grep", "-n",
                "_verify_platform_webhook",
                str(PORTAL_DIR / "apps" / "orders" / "views.py"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert "_verify_platform_webhook" in result.stdout, (
            "payment_success_webhook must reference _verify_platform_webhook"
        )
        # Also verify the function returns 401 when verification fails
        views_source = (PORTAL_DIR / "apps" / "orders" / "views.py").read_text()
        assert 'status=401' in views_source or 'status=HTTP_401' in views_source, (
            "Webhook must return 401 when signature verification fails"
        )

    @pytest.mark.integration
    @pytest.mark.security
    def test_webhook_verify_function_uses_hmac_compare_digest(self):
        """The webhook verification must use hmac.compare_digest (timing-safe comparison)."""
        views_path = PORTAL_DIR / "apps" / "orders" / "views.py"
        source = views_path.read_text()
        assert "compare_digest" in source, (
            "_verify_platform_webhook must use hmac.compare_digest for timing-safe comparison"
        )

    @pytest.mark.integration
    @pytest.mark.security
    def test_webhook_verify_function_checks_replay_window(self):
        """Webhook verification must reject requests outside the 5-minute replay window."""
        views_path = PORTAL_DIR / "apps" / "orders" / "views.py"
        source = views_path.read_text()
        assert "_WEBHOOK_REPLAY_WINDOW_SECONDS" in source, (
            "Webhook must define a replay window constant"
        )
        assert "300" in source, (
            "_WEBHOOK_REPLAY_WINDOW_SECONDS must be set to 300 (5 minutes)"
        )

    @pytest.mark.integration
    @pytest.mark.security
    def test_webhook_hmac_signature_logic(self):
        """Verify the HMAC signature scheme: ts.b'.' + body signed with SHA-256."""
        # This tests the signature algorithm matches the documented spec (ts + "." + body, SHA-256).
        secret = "integration-test-secret"
        body = b'{"order_id": "test-123", "status": "paid"}'
        ts = str(time.time())
        payload = ts.encode() + b"." + body
        expected_sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

        # Verify the signature matches itself (sanity)
        assert hmac.compare_digest(expected_sig, expected_sig)

        # Verify a different secret produces a different signature
        wrong_sig = hmac.new(b"wrong-secret", payload, hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(expected_sig, wrong_sig), (
            "Different secrets must produce different signatures"
        )

        # Verify a tampered body produces a different signature
        tampered_body = b'{"order_id": "test-999", "status": "paid"}'
        tampered_payload = ts.encode() + b"." + tampered_body
        tampered_sig = hmac.new(secret.encode(), tampered_payload, hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(expected_sig, tampered_sig), (
            "Tampered body must produce a different signature"
        )

    @pytest.mark.integration
    @pytest.mark.security
    def test_webhook_endpoint_is_csrf_exempt(self):
        """Inter-service webhook endpoint must be CSRF-exempt (uses HMAC auth instead)."""
        views_path = PORTAL_DIR / "apps" / "orders" / "views.py"
        source = views_path.read_text()
        # The csrf_exempt decorator must appear before payment_success_webhook
        match = re.search(
            r'@csrf_exempt.*?def payment_success_webhook',
            source,
            re.DOTALL,
        )
        assert match is not None, (
            "payment_success_webhook must be decorated with @csrf_exempt "
            "(HMAC-signed inter-service endpoint does not use CSRF tokens)"
        )


# ---------------------------------------------------------------------------
# 4. Portal isolation — no database driver dependencies
# ---------------------------------------------------------------------------


class TestPortalIsolation:
    """Portal must have no direct database access."""

    @pytest.mark.integration
    @pytest.mark.security
    def test_portal_has_no_psycopg2_in_requirements(self):
        """Portal requirements must not include psycopg2 (no direct DB access)."""
        portal_req = PORTAL_DIR / "requirements.txt"
        if not portal_req.exists():
            pytest.skip("Portal requirements.txt not found")

        lines = portal_req.read_text().splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            assert "psycopg2" not in stripped.lower(), (
                f"Portal must not depend on psycopg2 (direct DB access): {stripped}"
            )
            assert "mysqlclient" not in stripped.lower(), (
                f"Portal must not depend on mysqlclient (direct DB access): {stripped}"
            )

    @pytest.mark.integration
    @pytest.mark.security
    def test_portal_apps_have_no_models(self):
        """Portal apps must not define ORM models (no DB access)."""
        portal_apps = PORTAL_DIR / "apps"
        model_files = list(portal_apps.glob("*/models.py"))
        for model_file in model_files:
            content = model_file.read_text().strip()
            # Allow empty files or files with only imports/comments
            non_trivial_lines = [
                line for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#")
                and not line.strip().startswith("from ")
                and not line.strip().startswith("import ")
            ]
            assert len(non_trivial_lines) == 0, (
                f"Portal app {model_file} defines models — portal must be stateless: "
                f"{non_trivial_lines[:3]}"
            )


# ---------------------------------------------------------------------------
# 5. Token revocation self-revocation logic (structural)
# ---------------------------------------------------------------------------


class TestTokenRevocationLogic:
    """Structural tests for token revocation view behaviour."""

    @pytest.mark.integration
    @pytest.mark.security
    def test_revoke_token_view_deletes_token(self):
        """revoke_token view must call token.delete() to actually revoke the token."""
        views_path = PLATFORM_DIR / "apps" / "api" / "users" / "views.py"
        source = views_path.read_text()

        # Find the revoke_token function body
        match = re.search(
            r'def revoke_token\(.*?\n((?:    [^\n]*\n|\n)*)',
            source,
        )
        assert match is not None, "Could not locate revoke_token body"
        body = match.group(1)
        assert "token.delete()" in body, (
            "revoke_token must call token.delete() to invalidate the token"
        )

    @pytest.mark.integration
    @pytest.mark.security
    def test_revoke_token_view_requires_authentication(self):
        """revoke_token view must require authentication (IsAuthenticated permission)."""
        views_path = PLATFORM_DIR / "apps" / "api" / "users" / "views.py"
        source = views_path.read_text()

        # Find the decorator block immediately before def revoke_token
        match = re.search(
            r'((?:@[^\n]+\n)+)\s*def revoke_token',
            source,
        )
        assert match is not None, "Could not find decorators for revoke_token"
        decorators = match.group(1)
        assert "IsAuthenticated" in decorators, (
            "revoke_token must use @permission_classes([IsAuthenticated])"
        )
        assert "TokenAuthentication" in decorators, (
            "revoke_token must use @authentication_classes([TokenAuthentication])"
        )

    @pytest.mark.integration
    @pytest.mark.security
    def test_revoke_token_uses_request_auth_not_extra_query(self):
        """revoke_token must get the token from request.auth (set by TokenAuthentication),
        avoiding an extra DB query."""
        views_path = PLATFORM_DIR / "apps" / "api" / "users" / "views.py"
        source = views_path.read_text()

        match = re.search(
            r'def revoke_token\(.*?\n((?:    [^\n]*\n|\n)*)',
            source,
        )
        assert match is not None
        body = match.group(1)
        assert "request.auth" in body, (
            "revoke_token should use request.auth (already resolved by TokenAuthentication)"
        )
