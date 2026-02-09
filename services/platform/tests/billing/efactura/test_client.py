"""
Tests for ANAF e-Factura API client.
"""

from datetime import timedelta
from unittest.mock import Mock, patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.client import (
    AuthenticationError,
    EFacturaClient,
    EFacturaConfig,
    EFacturaEnvironment,
    MessageInfo,
    NetworkError,
    StatusResponse,
    TokenResponse,
    UploadResponse,
)


class EFacturaEnvironmentTestCase(TestCase):
    """Test EFacturaEnvironment enum."""

    def test_test_environment_base_url(self):
        """Test base URL for test environment."""
        env = EFacturaEnvironment.TEST
        self.assertEqual(env.base_url, "https://api.anaf.ro/test/FCTEL/rest")

    def test_production_environment_base_url(self):
        """Test base URL for production environment."""
        env = EFacturaEnvironment.PRODUCTION
        self.assertEqual(env.base_url, "https://api.anaf.ro/prod/FCTEL/rest")

    def test_oauth_base_url(self):
        """Test OAuth base URL."""
        env = EFacturaEnvironment.TEST
        self.assertEqual(env.oauth_base_url, "https://logincert.anaf.ro/anaf-oauth2/v1")


class EFacturaConfigTestCase(TestCase):
    """Test EFacturaConfig dataclass."""

    def test_config_creation(self):
        """Test creating config manually."""
        config = EFacturaConfig(
            client_id="test-client",
            client_secret="test-secret",
            company_cui="12345678",
        )
        self.assertEqual(config.client_id, "test-client")
        self.assertEqual(config.environment, EFacturaEnvironment.TEST)

    @override_settings(
        EFACTURA_CLIENT_ID="settings-client",
        EFACTURA_CLIENT_SECRET="settings-secret",
        EFACTURA_COMPANY_CUI="87654321",
        EFACTURA_ENVIRONMENT="test",
    )
    def test_config_from_settings(self):
        """Test creating config from Django settings."""
        config = EFacturaConfig.from_settings()
        self.assertEqual(config.client_id, "settings-client")
        self.assertEqual(config.client_secret, "settings-secret")
        self.assertEqual(config.company_cui, "87654321")
        self.assertEqual(config.environment, EFacturaEnvironment.TEST)

    @override_settings(EFACTURA_ENVIRONMENT="production")
    def test_config_production_environment(self):
        """Test production environment from settings."""
        config = EFacturaConfig.from_settings()
        self.assertEqual(config.environment, EFacturaEnvironment.PRODUCTION)

    def test_config_is_valid(self):
        """Test config validation."""
        valid_config = EFacturaConfig(
            client_id="test",
            client_secret="secret",
            company_cui="12345678",
        )
        self.assertTrue(valid_config.is_valid())

        invalid_config = EFacturaConfig(
            client_id="",
            client_secret="secret",
            company_cui="12345678",
        )
        self.assertFalse(invalid_config.is_valid())

    def test_config_urls(self):
        """Test derived URL properties."""
        config = EFacturaConfig(
            client_id="test",
            client_secret="secret",
            company_cui="12345678",
            environment=EFacturaEnvironment.TEST,
        )
        self.assertEqual(config.base_url, "https://api.anaf.ro/test/FCTEL/rest")
        self.assertIn("authorize", config.oauth_authorize_url)
        self.assertIn("token", config.oauth_token_url)


class TokenResponseTestCase(TestCase):
    """Test TokenResponse dataclass."""

    def test_token_from_dict(self):
        """Test creating token from dict."""
        data = {
            "access_token": "test-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-token",
        }
        token = TokenResponse.from_dict(data)
        self.assertEqual(token.access_token, "test-token")
        self.assertEqual(token.token_type, "Bearer")
        self.assertEqual(token.refresh_token, "refresh-token")

    def test_token_expiration(self):
        """Test token expiration check."""
        # Fresh token
        token = TokenResponse(
            access_token="test",
            token_type="Bearer",
            expires_in=3600,
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.assertFalse(token.is_expired)

        # Expired token
        expired_token = TokenResponse(
            access_token="test",
            token_type="Bearer",
            expires_in=3600,
            expires_at=timezone.now() - timedelta(hours=1),
        )
        self.assertTrue(expired_token.is_expired)


class UploadResponseTestCase(TestCase):
    """Test UploadResponse dataclass."""

    def test_successful_response(self):
        """Test parsing successful upload response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"index_incarcare": "12345", "message": "OK"}'
        mock_response.json.return_value = {"index_incarcare": "12345", "message": "OK"}

        result = UploadResponse.from_response(mock_response)
        self.assertTrue(result.success)
        self.assertEqual(result.upload_index, "12345")

    def test_failed_response(self):
        """Test parsing failed upload response."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = '{"message": "Validation failed", "errors": ["Invalid CUI"]}'
        mock_response.json.return_value = {"message": "Validation failed", "errors": ["Invalid CUI"]}

        result = UploadResponse.from_response(mock_response)
        self.assertFalse(result.success)
        self.assertIn("Invalid CUI", result.errors)

    def test_error_with_string_errors(self):
        """Test parsing error with string instead of list."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = '{"errors": "Single error message"}'
        mock_response.json.return_value = {"errors": "Single error message"}

        result = UploadResponse.from_response(mock_response)
        self.assertFalse(result.success)
        self.assertIn("Single error message", result.errors)

    def test_error_factory_method(self):
        """Test error factory method."""
        result = UploadResponse.error("Test error")
        self.assertFalse(result.success)
        self.assertEqual(result.message, "Test error")
        self.assertIn("Test error", result.errors)


class StatusResponseTestCase(TestCase):
    """Test StatusResponse dataclass."""

    def test_processing_status(self):
        """Test in processing status."""
        mock_response = Mock()
        mock_response.text = '{"stare": "in processing"}'
        mock_response.json.return_value = {"stare": "in processing"}

        result = StatusResponse.from_response(mock_response)
        self.assertTrue(result.is_processing)
        self.assertFalse(result.is_accepted)
        self.assertFalse(result.is_rejected)

    def test_accepted_status(self):
        """Test accepted status."""
        mock_response = Mock()
        mock_response.text = '{"stare": "ok", "id_descarcare": "67890"}'
        mock_response.json.return_value = {"stare": "ok", "id_descarcare": "67890"}

        result = StatusResponse.from_response(mock_response)
        self.assertTrue(result.is_accepted)
        self.assertEqual(result.download_id, "67890")

    def test_rejected_status(self):
        """Test rejected status."""
        mock_response = Mock()
        mock_response.text = '{"stare": "nok", "Errors": [{"message": "Invalid XML"}]}'
        mock_response.json.return_value = {"stare": "nok", "Errors": [{"message": "Invalid XML"}]}

        result = StatusResponse.from_response(mock_response)
        self.assertTrue(result.is_rejected)
        self.assertEqual(len(result.errors), 1)

    def test_romanian_processing_status(self):
        """Test Romanian language processing status."""
        result = StatusResponse(status="in curs de procesare")
        self.assertTrue(result.is_processing)


class MessageInfoTestCase(TestCase):
    """Test MessageInfo dataclass."""

    def test_from_dict(self):
        """Test creating MessageInfo from dict."""
        data = {
            "id": "msg-123",
            "id_solicitare": "req-456",
            "data_creare": "2024-12-26T10:00:00",
            "tip": "factura",
            "cif": "12345678",
            "detalii": "Test message",
        }
        info = MessageInfo.from_dict(data)
        self.assertEqual(info.message_id, "msg-123")
        self.assertEqual(info.upload_index, "req-456")
        self.assertEqual(info.cif, "12345678")


class EFacturaClientTestCase(TestCase):
    """Test EFacturaClient."""

    def setUp(self):
        self.config = EFacturaConfig(
            client_id="test-client",
            client_secret="test-secret",
            company_cui="12345678",
        )
        self.client = EFacturaClient(self.config)

    def tearDown(self):
        self.client.close()

    def test_context_manager(self):
        """Test client as context manager."""
        with EFacturaClient(self.config) as client:
            self.assertIsNotNone(client.session)
        # Session should be closed after exiting context

    def test_get_authorization_url(self):
        """Test OAuth authorization URL generation."""
        url = self.client.get_authorization_url(
            redirect_uri="https://example.com/callback",
            state="test-state",
        )
        self.assertIn("authorize", url)
        self.assertIn("test-client", url)
        self.assertIn("test-state", url)
        self.assertIn("redirect_uri", url)

    @patch("apps.billing.efactura.client.EFacturaClient._get_access_token")
    @patch("apps.billing.efactura.client.EFacturaClient._request_with_retry")
    def test_upload_invoice_success(self, mock_request, mock_token):
        """Test successful invoice upload."""
        mock_token.return_value = "test-token"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"index_incarcare": "12345"}'
        mock_response.json.return_value = {"index_incarcare": "12345"}
        mock_request.return_value = mock_response

        xml = "<Invoice>test</Invoice>"
        result = self.client.upload_invoice(xml)

        self.assertTrue(result.success)
        self.assertEqual(result.upload_index, "12345")
        mock_request.assert_called_once()

    def test_upload_invoice_invalid_config(self):
        """Test upload with invalid config."""
        client = EFacturaClient(EFacturaConfig(
            client_id="",
            client_secret="",
            company_cui="",
        ))
        result = client.upload_invoice("<Invoice/>")
        self.assertFalse(result.success)
        self.assertIn("Invalid", result.message)

    @patch("apps.billing.efactura.client.EFacturaClient._get_access_token")
    @patch("apps.billing.efactura.client.EFacturaClient._request_with_retry")
    def test_get_upload_status(self, mock_request, mock_token):
        """Test getting upload status."""
        mock_token.return_value = "test-token"

        mock_response = Mock()
        mock_response.text = '{"stare": "ok", "id_descarcare": "67890"}'
        mock_response.json.return_value = {"stare": "ok", "id_descarcare": "67890"}
        mock_request.return_value = mock_response

        result = self.client.get_upload_status("12345")

        self.assertTrue(result.is_accepted)
        self.assertEqual(result.download_id, "67890")

    @patch("apps.billing.efactura.client.EFacturaClient._get_access_token")
    @patch("apps.billing.efactura.client.EFacturaClient._request_with_retry")
    def test_download_response(self, mock_request, mock_token):
        """Test downloading response."""
        mock_token.return_value = "test-token"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"%PDF-1.4 test content"
        mock_request.return_value = mock_response

        result = self.client.download_response("67890")

        self.assertEqual(result, b"%PDF-1.4 test content")

    @patch("apps.billing.efactura.client.EFacturaClient._get_access_token")
    @patch("apps.billing.efactura.client.EFacturaClient._request_with_retry")
    def test_download_response_failure(self, mock_request, mock_token):
        """Test download failure."""
        mock_token.return_value = "test-token"

        mock_response = Mock()
        mock_response.status_code = 404
        mock_request.return_value = mock_response

        with self.assertRaises(NetworkError):
            self.client.download_response("invalid-id")

    @patch("apps.billing.efactura.client.EFacturaClient._get_access_token")
    @patch("apps.billing.efactura.client.EFacturaClient._request_with_retry")
    def test_list_messages(self, mock_request, mock_token):
        """Test listing messages."""
        mock_token.return_value = "test-token"

        mock_response = Mock()
        mock_response.text = '{"mesaje": [{"id": "msg-1", "tip": "factura"}]}'
        mock_response.json.return_value = {
            "mesaje": [{"id": "msg-1", "tip": "factura", "cif": "12345678"}]
        }
        mock_request.return_value = mock_response

        result = self.client.list_messages(days=30)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].message_id, "msg-1")

    @patch("apps.billing.efactura.client.EFacturaClient._get_access_token")
    def test_upload_no_token(self, mock_token):
        """Test upload when no token available."""
        mock_token.side_effect = AuthenticationError("No token")

        with self.assertRaises(AuthenticationError):
            self.client.upload_invoice("<Invoice/>")

    @patch.object(EFacturaClient, "session")
    def test_request_with_retry_success(self, mock_session):
        """Test request with successful response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.request.return_value = mock_response

        result = self.client._request_with_retry("GET", "http://test.com")
        self.assertEqual(result.status_code, 200)

    @patch.object(EFacturaClient, "session")
    @patch("apps.billing.efactura.client.time.sleep")
    def test_request_with_retry_rate_limit(self, mock_sleep, mock_session):
        """Test request with rate limit retry."""
        rate_limited = Mock()
        rate_limited.status_code = 429
        rate_limited.headers = {"Retry-After": "1"}

        success = Mock()
        success.status_code = 200

        mock_session.request.side_effect = [rate_limited, success]

        result = self.client._request_with_retry("GET", "http://test.com")
        self.assertEqual(result.status_code, 200)
        mock_sleep.assert_called_once_with(1)

    @patch.object(EFacturaClient, "session")
    @patch("apps.billing.efactura.client.time.sleep")
    def test_request_with_retry_timeout(self, mock_sleep, mock_session):
        """Test request with timeout retry."""
        import requests

        mock_session.request.side_effect = requests.Timeout()

        with self.assertRaises(NetworkError):
            self.client._request_with_retry("GET", "http://test.com")

        # Should have retried max_retries times
        self.assertEqual(mock_session.request.call_count, self.config.max_retries)

    @patch("apps.billing.efactura.client.EFacturaClient._get_access_token")
    @patch("apps.billing.efactura.client.EFacturaClient._request_with_retry")
    def test_upload_credit_note(self, mock_request, mock_token):
        """Test credit note upload uses correct standard."""
        mock_token.return_value = "test-token"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"index_incarcare": "12345"}'
        mock_response.json.return_value = {"index_incarcare": "12345"}
        mock_request.return_value = mock_response

        self.client.upload_credit_note("<CreditNote/>")

        # Verify CN standard was used
        call_kwargs = mock_request.call_args
        self.assertIn("CN", str(call_kwargs))

    @patch("apps.billing.efactura.client.EFacturaClient._get_access_token")
    @patch("apps.billing.efactura.client.EFacturaClient._request_with_retry")
    def test_validate_xml(self, mock_request, mock_token):
        """Test XML validation."""
        mock_token.return_value = "test-token"

        mock_response = Mock()
        mock_response.text = '{"stare": "ok"}'
        mock_response.json.return_value = {"stare": "ok"}
        mock_request.return_value = mock_response

        result = self.client.validate_xml("<Invoice/>")
        self.assertTrue(result.is_accepted)

    @patch("apps.billing.efactura.client.EFacturaClient._get_access_token")
    @patch("apps.billing.efactura.client.EFacturaClient._request_with_retry")
    def test_convert_to_pdf(self, mock_request, mock_token):
        """Test PDF conversion."""
        mock_token.return_value = "test-token"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"%PDF-1.4 converted"
        mock_request.return_value = mock_response

        result = self.client.convert_to_pdf("<Invoice/>")
        self.assertEqual(result, b"%PDF-1.4 converted")


class TokenCachingTestCase(TestCase):
    """Test token caching behavior."""

    def setUp(self):
        self.config = EFacturaConfig(
            client_id="test-client",
            client_secret="test-secret",
            company_cui="12345678",
        )
        self.client = EFacturaClient(self.config)

    @patch("apps.billing.efactura.client.cache")
    def test_cache_token(self, mock_cache):
        """Test token caching."""
        token = TokenResponse(
            access_token="test-token",
            token_type="Bearer",
            expires_in=3600,
        )

        self.client._cache_token(token)

        mock_cache.set.assert_called_once()
        call_args = mock_cache.set.call_args
        self.assertIn("efactura_token", call_args[0][0])

    @patch("apps.billing.efactura.client.cache")
    def test_get_cached_token(self, mock_cache):
        """Test getting cached token."""
        mock_cache.get.return_value = {
            "access_token": "cached-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "",
            "scope": "",
            "expires_at": timezone.now() + timedelta(hours=1),
        }

        token = self.client._get_cached_token()
        self.assertEqual(token.access_token, "cached-token")

    @patch("apps.billing.efactura.client.cache")
    def test_get_cached_token_not_found(self, mock_cache):
        """Test getting non-existent cached token."""
        mock_cache.get.return_value = None

        token = self.client._get_cached_token()
        self.assertIsNone(token)


class AuthenticationFlowTestCase(TestCase):
    """Test OAuth2 authentication flow."""

    def setUp(self):
        self.config = EFacturaConfig(
            client_id="test-client",
            client_secret="test-secret",
            company_cui="12345678",
        )
        self.client = EFacturaClient(self.config)

    @patch.object(EFacturaClient, "session")
    @patch.object(EFacturaClient, "_cache_token")
    def test_exchange_code_for_token(self, mock_cache, mock_session):
        """Test exchanging auth code for token."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh",
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response

        token = self.client.exchange_code_for_token(
            code="auth-code",
            redirect_uri="https://example.com/callback",
        )

        self.assertEqual(token.access_token, "new-token")
        mock_cache.assert_called_once()

    @patch.object(EFacturaClient, "session")
    def test_exchange_code_failure(self, mock_session):
        """Test auth code exchange failure."""
        import requests

        mock_session.post.side_effect = requests.RequestException("Connection failed")

        with self.assertRaises(AuthenticationError):
            self.client.exchange_code_for_token("code", "redirect")

    @patch.object(EFacturaClient, "session")
    @patch.object(EFacturaClient, "_cache_token")
    def test_refresh_token(self, mock_cache, mock_session):
        """Test refreshing token."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "refreshed-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response

        token = self.client.refresh_token("old-refresh-token")

        self.assertEqual(token.access_token, "refreshed-token")

    @patch.object(EFacturaClient, "_get_cached_token")
    @override_settings(EFACTURA_ACCESS_TOKEN="manual-token")
    def test_get_access_token_from_settings(self, mock_cached):
        """Test fallback to manual token from settings."""
        mock_cached.return_value = None  # No cached token

        token = self.client._get_access_token()
        self.assertEqual(token, "manual-token")

    @patch.object(EFacturaClient, "_get_cached_token")
    @override_settings(EFACTURA_ACCESS_TOKEN="")
    def test_get_access_token_no_token(self, mock_cached):
        """Test error when no token available."""
        mock_cached.return_value = None

        with self.assertRaises(AuthenticationError):
            self.client._get_access_token()
