"""
ANAF e-Factura API client with OAuth2 authentication.

This client handles all communication with the Romanian ANAF e-Factura API:
- OAuth2 authentication with certificate-based authorization
- Invoice/Credit Note upload
- Status checking
- Response download
- Message listing

Reference:
- https://static.anaf.ro/static/10/Anaf/Informatii_R/API/Oauth_procedura_inregistrare_aplicatii_portal_ANAF.pdf
- https://mfinante.gov.ro/web/efactura/informatii-tehnice
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, ClassVar
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)


class EFacturaEnvironment(StrEnum):
    """ANAF API environment."""

    TEST = "test"
    PRODUCTION = "prod"

    @property
    def base_url(self) -> str:
        """Get base URL for this environment."""
        return f"https://api.anaf.ro/{self.value}/FCTEL/rest"

    @property
    def oauth_base_url(self) -> str:
        """Get OAuth base URL."""
        return "https://logincert.anaf.ro/anaf-oauth2/v1"


@dataclass
class EFacturaConfig:
    """Configuration for e-Factura API client."""

    client_id: str
    client_secret: str
    company_cui: str
    environment: EFacturaEnvironment = EFacturaEnvironment.TEST
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0

    @classmethod
    def from_settings(cls) -> EFacturaConfig:
        """Create config from Django settings and SettingsService."""
        from apps.settings.services import SettingsService  # noqa: PLC0415

        env_str = getattr(settings, "EFACTURA_ENVIRONMENT", "test")
        environment = EFacturaEnvironment.PRODUCTION if env_str == "production" else EFacturaEnvironment.TEST

        return cls(
            client_id=getattr(settings, "EFACTURA_CLIENT_ID", ""),
            client_secret=getattr(settings, "EFACTURA_CLIENT_SECRET", ""),
            company_cui=getattr(settings, "EFACTURA_COMPANY_CUI", ""),
            environment=environment,
            timeout=SettingsService.get_integer_setting("billing.efactura_api_timeout_seconds", 30),
            max_retries=SettingsService.get_integer_setting("billing.efactura_api_max_retries", 3),
        )

    @property
    def base_url(self) -> str:
        return self.environment.base_url

    @property
    def oauth_authorize_url(self) -> str:
        return f"{self.environment.oauth_base_url}/authorize"

    @property
    def oauth_token_url(self) -> str:
        return f"{self.environment.oauth_base_url}/token"

    def is_valid(self) -> bool:
        """Check if configuration has required fields."""
        return bool(self.client_id and self.client_secret and self.company_cui)


@dataclass
class TokenResponse:
    """OAuth2 token response."""

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str = ""
    scope: str = ""
    expires_at: datetime = field(default_factory=timezone.now)

    def __post_init__(self) -> None:
        if self.expires_at == timezone.now():
            self.expires_at = timezone.now() + timedelta(seconds=self.expires_in - 60)

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    @classmethod
    def from_dict(cls, data: dict) -> TokenResponse:
        return cls(
            access_token=data.get("access_token", ""),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 3600),
            refresh_token=data.get("refresh_token", ""),
            scope=data.get("scope", ""),
        )


@dataclass
class UploadResponse:
    """Response from upload endpoint."""

    success: bool
    upload_index: str = ""  # index_incarcare
    message: str = ""
    errors: list[str] = field(default_factory=list)
    raw_response: dict = field(default_factory=dict)

    @classmethod
    def from_response(cls, response: requests.Response) -> UploadResponse:
        """Parse upload response."""
        try:
            data = response.json() if response.text else {}
        except json.JSONDecodeError:
            data = {"raw_text": response.text}

        if response.status_code == 200:
            return cls(
                success=True,
                upload_index=data.get("index_incarcare", ""),
                message=data.get("message", "Upload successful"),
                raw_response=data,
            )
        else:
            errors = data.get("errors", [])
            if isinstance(errors, str):
                errors = [errors]
            elif not errors and "message" in data:
                errors = [data["message"]]
            elif not errors:
                errors = [f"HTTP {response.status_code}: {response.text[:200]}"]

            return cls(
                success=False,
                message=data.get("message", "Upload failed"),
                errors=errors,
                raw_response=data,
            )

    @classmethod
    def error(cls, message: str) -> UploadResponse:
        """Create error response."""
        return cls(success=False, message=message, errors=[message])


@dataclass
class StatusResponse:
    """Response from status check endpoint."""

    status: str  # 'in processing', 'ok', 'nok'
    download_id: str = ""  # id_descarcare
    errors: list[dict] = field(default_factory=list)
    raw_response: dict = field(default_factory=dict)

    @property
    def is_processing(self) -> bool:
        return self.status.lower() in ("in processing", "in curs de procesare")

    @property
    def is_accepted(self) -> bool:
        return self.status.lower() == "ok"

    @property
    def is_rejected(self) -> bool:
        return self.status.lower() == "nok"

    @classmethod
    def from_response(cls, response: requests.Response) -> StatusResponse:
        """Parse status response."""
        try:
            data = response.json() if response.text else {}
        except json.JSONDecodeError:
            data = {"raw_text": response.text}

        status = data.get("stare", data.get("status", "unknown"))
        download_id = data.get("id_descarcare", "")
        errors = data.get("Errors", data.get("errors", []))

        if isinstance(errors, str):
            errors = [{"message": errors}]
        elif isinstance(errors, list):
            errors = [{"message": e} if isinstance(e, str) else e for e in errors]

        return cls(
            status=status,
            download_id=download_id,
            errors=errors,
            raw_response=data,
        )

    @classmethod
    def error(cls, message: str) -> StatusResponse:
        """Create error response."""
        return cls(status="error", errors=[{"message": message}])


@dataclass
class MessageInfo:
    """Information about a message from ANAF."""

    message_id: str
    upload_index: str
    download_id: str
    creation_date: str
    message_type: str
    cif: str
    details: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> MessageInfo:
        return cls(
            message_id=data.get("id", ""),
            upload_index=data.get("id_solicitare", ""),
            download_id=data.get("id", ""),
            creation_date=data.get("data_creare", ""),
            message_type=data.get("tip", ""),
            cif=data.get("cif", ""),
            details=data.get("detalii", ""),
        )


class EFacturaClientError(Exception):
    """Base exception for e-Factura client errors."""


class AuthenticationError(EFacturaClientError):
    """Authentication failed."""


class NetworkError(EFacturaClientError):
    """Network communication failed."""


class ValidationError(EFacturaClientError):
    """XML validation failed."""


class RateLimitError(EFacturaClientError):
    """Rate limit exceeded."""


class EFacturaClient:
    """
    Client for Romanian ANAF e-Factura API.

    Handles OAuth2 authentication and all e-Factura operations.

    Usage:
        config = EFacturaConfig.from_settings()
        client = EFacturaClient(config)

        # Upload invoice
        response = client.upload_invoice(xml_content)
        if response.success:
            # Check status
            status = client.get_upload_status(response.upload_index)
    """

    # Token cache key prefix
    TOKEN_CACHE_KEY: ClassVar[str] = "efactura_token_{env}"  # noqa: S105

    def __init__(self, config: EFacturaConfig | None = None):
        self.config = config or EFacturaConfig.from_settings()
        self._session: requests.Session | None = None
        self._token: TokenResponse | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create HTTP session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update(
                {
                    "Accept": "application/json",
                    "User-Agent": "PRAHO-EFactura/1.0",
                }
            )
        return self._session

    def close(self) -> None:
        """Close HTTP session."""
        if self._session is not None:
            self._session.close()
            self._session = None

    def __enter__(self) -> EFacturaClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # --- Authentication ---

    def get_authorization_url(self, redirect_uri: str, state: str) -> str:
        """
        Generate OAuth2 authorization URL for user consent.

        Note: ANAF OAuth2 requires certificate-based authentication.
        The user must have their digital certificate installed in browser.

        Args:
            redirect_uri: Callback URL registered with ANAF
            state: CSRF protection token

        Returns:
            Authorization URL to redirect user to
        """
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "token_content_type": "jwt",
        }
        return f"{self.config.oauth_authorize_url}?{urlencode(params)}"

    def exchange_code_for_token(self, code: str, redirect_uri: str) -> TokenResponse:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code from callback
            redirect_uri: Same redirect URI used in authorization

        Returns:
            TokenResponse with access token

        Raises:
            AuthenticationError: If token exchange fails
        """
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }

        try:
            response = self.session.post(
                self.config.oauth_token_url,
                data=data,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            token = TokenResponse.from_dict(response.json())
            self._cache_token(token)
            return token
        except requests.RequestException as e:
            logger.error(f"Token exchange failed: {e}")
            raise AuthenticationError(f"Failed to exchange code for token: {e}") from e

    def refresh_token(self, refresh_token: str) -> TokenResponse:
        """
        Refresh expired access token.

        Args:
            refresh_token: Refresh token from previous authentication

        Returns:
            New TokenResponse

        Raises:
            AuthenticationError: If refresh fails
        """
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }

        try:
            response = self.session.post(
                self.config.oauth_token_url,
                data=data,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            token = TokenResponse.from_dict(response.json())
            self._cache_token(token)
            return token
        except requests.RequestException as e:
            logger.error(f"Token refresh failed: {e}")
            raise AuthenticationError(f"Failed to refresh token: {e}") from e

    def _get_access_token(self) -> str:
        """Get valid access token, refreshing if needed."""
        # Check cached token
        token = self._get_cached_token()
        if token and not token.is_expired:
            return token.access_token

        # Try to refresh
        if token and token.refresh_token:
            try:
                token = self.refresh_token(token.refresh_token)
                return token.access_token
            except AuthenticationError:
                pass

        # Check for manually configured token (for development)
        manual_token = getattr(settings, "EFACTURA_ACCESS_TOKEN", "")
        if manual_token:
            return manual_token

        raise AuthenticationError("No valid access token. User must complete OAuth2 authorization flow.")

    def _cache_token(self, token: TokenResponse) -> None:
        """Cache token with expiration."""
        cache_key = self.TOKEN_CACHE_KEY.format(env=self.config.environment.value)
        cache.set(cache_key, token.__dict__, timeout=token.expires_in - 60)
        self._token = token

    def _get_cached_token(self) -> TokenResponse | None:
        """Get token from cache."""
        if self._token and not self._token.is_expired:
            return self._token

        cache_key = self.TOKEN_CACHE_KEY.format(env=self.config.environment.value)
        data = cache.get(cache_key)
        if data:
            self._token = TokenResponse(**data)
            return self._token
        return None

    # --- Document Operations ---

    def upload_invoice(
        self,
        xml_content: str,
        *,
        standard: str = "UBL",
        cif: str | None = None,
        extern: bool = False,
        autofactura: bool = False,
    ) -> UploadResponse:
        """
        Upload invoice XML to ANAF.

        Args:
            xml_content: UBL 2.1 XML document as string
            standard: Document standard (UBL, CN for Credit Note, CII, RASP)
            cif: Company CUI (numeric, without 'RO' prefix). Uses config if not provided.
            extern: True if buyer is non-Romanian
            autofactura: True if self-invoicing

        Returns:
            UploadResponse with upload_index for status tracking

        Raises:
            AuthenticationError: If not authenticated
            NetworkError: If network request fails
        """
        if not self.config.is_valid():
            return UploadResponse.error("Invalid e-Factura configuration")

        params: dict[str, str] = {
            "standard": standard,
            "cif": cif or self.config.company_cui,
        }
        if extern:
            params["extern"] = "DA"
        if autofactura:
            params["autofactura"] = "DA"

        try:
            access_token = self._get_access_token()

            response = self._request_with_retry(
                "POST",
                f"{self.config.base_url}/upload",
                params=params,
                data=xml_content.encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/xml; charset=utf-8",
                },
            )

            result = UploadResponse.from_response(response)

            if result.success:
                logger.info(f"e-Factura uploaded successfully: {result.upload_index}")
            else:
                logger.warning(f"e-Factura upload failed: {result.errors}")

            return result

        except AuthenticationError:
            raise
        except requests.RequestException as e:
            logger.error(f"e-Factura upload failed: {e}")
            raise NetworkError(f"Failed to upload e-Factura: {e}") from e

    def upload_credit_note(
        self,
        xml_content: str,
        *,
        cif: str | None = None,
    ) -> UploadResponse:
        """Upload credit note XML to ANAF."""
        return self.upload_invoice(xml_content, standard="CN", cif=cif)

    def get_upload_status(self, upload_index: str) -> StatusResponse:
        """
        Check status of uploaded document.

        Args:
            upload_index: The index_incarcare from upload response

        Returns:
            StatusResponse with current status

        Raises:
            NetworkError: If request fails
        """
        try:
            access_token = self._get_access_token()

            response = self._request_with_retry(
                "GET",
                f"{self.config.base_url}/stareMesaj",
                params={"id_incarcare": upload_index},
                headers={"Authorization": f"Bearer {access_token}"},
            )

            result = StatusResponse.from_response(response)
            logger.info(f"e-Factura status for {upload_index}: {result.status}")
            return result

        except AuthenticationError:
            raise
        except requests.RequestException as e:
            logger.error(f"e-Factura status check failed: {e}")
            raise NetworkError(f"Failed to check status: {e}") from e

    def download_response(self, download_id: str) -> bytes:
        """
        Download processed e-Factura response.

        This returns the signed PDF or error details after processing.

        Args:
            download_id: The id_descarcare from status response

        Returns:
            Response content as bytes (usually ZIP containing PDF)

        Raises:
            NetworkError: If download fails
        """
        try:
            access_token = self._get_access_token()

            response = self._request_with_retry(
                "GET",
                f"{self.config.base_url}/descarcare",
                params={"id": download_id},
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if response.status_code == 200:
                logger.info(f"e-Factura response downloaded: {download_id}")
                return response.content
            else:
                raise NetworkError(f"Download failed with status {response.status_code}")

        except AuthenticationError:
            raise
        except requests.RequestException as e:
            logger.error(f"e-Factura download failed: {e}")
            raise NetworkError(f"Failed to download response: {e}") from e

    def list_messages(
        self,
        days: int = 60,
        cif: str | None = None,
        filter_type: str | None = None,
    ) -> list[MessageInfo]:
        """
        List available messages from ANAF.

        Args:
            days: Number of days to query (1-60)
            cif: Company CUI
            filter_type: 'E' for errors only, 'T' for all, 'P' for paginated

        Returns:
            List of MessageInfo objects

        Raises:
            NetworkError: If request fails
        """
        params: dict[str, Any] = {
            "zile": min(max(days, 1), 60),
            "cif": cif or self.config.company_cui,
        }
        if filter_type:
            params["filtru"] = filter_type

        try:
            access_token = self._get_access_token()

            response = self._request_with_retry(
                "GET",
                f"{self.config.base_url}/listaMesaje",
                params=params,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            data = response.json() if response.text else {}
            messages = data.get("mesaje", data.get("messages", []))
            return [MessageInfo.from_dict(m) for m in messages]

        except AuthenticationError:
            raise
        except requests.RequestException as e:
            logger.error(f"e-Factura list messages failed: {e}")
            raise NetworkError(f"Failed to list messages: {e}") from e

    def validate_xml(self, xml_content: str, standard: str = "UBL") -> StatusResponse:
        """
        Validate XML against ANAF schema (optional pre-upload check).

        Args:
            xml_content: XML to validate
            standard: Document standard

        Returns:
            StatusResponse with validation result
        """
        params = {
            "standard": standard,
        }

        try:
            access_token = self._get_access_token()

            response = self._request_with_retry(
                "POST",
                f"{self.config.base_url}/validare",
                params=params,
                data=xml_content.encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/xml; charset=utf-8",
                },
            )

            return StatusResponse.from_response(response)

        except AuthenticationError:
            raise
        except requests.RequestException as e:
            logger.error(f"e-Factura validation failed: {e}")
            raise NetworkError(f"Failed to validate XML: {e}") from e

    def convert_to_pdf(self, xml_content: str, standard: str = "UBL") -> bytes:
        """
        Convert XML to PDF visualization.

        Args:
            xml_content: UBL XML to convert
            standard: Document standard

        Returns:
            PDF content as bytes
        """
        params = {
            "standard": standard,
        }

        try:
            access_token = self._get_access_token()

            response = self._request_with_retry(
                "POST",
                f"{self.config.base_url}/transformare",
                params=params,
                data=xml_content.encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/xml; charset=utf-8",
                },
            )

            if response.status_code == 200:
                return response.content
            else:
                raise NetworkError(f"PDF conversion failed with status {response.status_code}")

        except AuthenticationError:
            raise
        except requests.RequestException as e:
            logger.error(f"e-Factura PDF conversion failed: {e}")
            raise NetworkError(f"Failed to convert to PDF: {e}") from e

    # --- Internal Methods ---

    def _request_with_retry(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:
        """Make HTTP request with retry logic."""
        kwargs.setdefault("timeout", self.config.timeout)
        last_error: Exception | None = None

        for attempt in range(self.config.max_retries):
            try:
                response = self.session.request(method, url, **kwargs)

                # Check for rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    logger.warning(f"Rate limited, waiting {retry_after}s")
                    time.sleep(retry_after)
                    continue

                return response

            except requests.Timeout as e:
                last_error = e
                logger.warning(f"Request timeout (attempt {attempt + 1}/{self.config.max_retries})")
            except requests.ConnectionError as e:
                last_error = e
                logger.warning(f"Connection error (attempt {attempt + 1}/{self.config.max_retries})")

            # Wait before retry (exponential backoff)
            if attempt < self.config.max_retries - 1:
                delay = self.config.retry_delay * (2**attempt)
                time.sleep(delay)

        raise NetworkError(f"Request failed after {self.config.max_retries} attempts: {last_error}")
