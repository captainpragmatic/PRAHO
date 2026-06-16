# OUTBOUND_HTTP_MIGRATION: pending  # noqa: ERA001
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

import base64
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from http import HTTPStatus
from typing import Any, ClassVar
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.common.outbound_http import OutboundPolicy, safe_request
from apps.settings.services import SettingsService

logger = logging.getLogger(__name__)

EFACTURA_POLICY = OutboundPolicy(
    name="efactura",
    allowed_domains=frozenset({"anaf.ro", "mfinante.gov.ro"}),
    timeout_seconds=30.0,
    max_retries=0,  # Retries handled by _request_with_retry
)

# Maximum Retry-After sleep to prevent unbounded waits
MAX_RETRY_AFTER_SECONDS = 120


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
    # Gap 2/7 (#123): the exact upload Content-Type and document standard are part of the
    # credential-gated contract. Documented defaults; overridable. LIVE-VERIFY against the sandbox.
    upload_content_type: str = "application/xml; charset=utf-8"
    default_standard: str = "UBL"

    @classmethod
    def from_settings(cls) -> EFacturaConfig:
        """Create config from Django settings and SettingsService."""
        env_str = getattr(settings, "EFACTURA_ENVIRONMENT", "test")
        environment = EFacturaEnvironment.PRODUCTION if env_str == "production" else EFacturaEnvironment.TEST

        return cls(
            client_id=getattr(settings, "EFACTURA_CLIENT_ID", ""),
            client_secret=getattr(settings, "EFACTURA_CLIENT_SECRET", ""),
            company_cui=getattr(settings, "EFACTURA_COMPANY_CUI", ""),
            environment=environment,
            timeout=SettingsService.get_integer_setting("billing.efactura_api_timeout_seconds", 30),
            max_retries=SettingsService.get_integer_setting("billing.efactura_api_max_retries", 3),
            upload_content_type=getattr(settings, "EFACTURA_UPLOAD_CONTENT_TYPE", "application/xml; charset=utf-8"),
            default_standard=getattr(settings, "EFACTURA_UPLOAD_STANDARD", "UBL"),
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
    def from_dict(cls, data: dict[str, Any]) -> TokenResponse:
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
    raw_response: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_response(cls, response: requests.Response) -> UploadResponse:
        """Parse an ANAF upload response.

        ANAF returns an XML ``<header>`` (NOT JSON) for /upload and /uploadb2c:
        ``ExecutionStatus="0"`` + ``index_incarcare`` on success, ``ExecutionStatus="1"`` with
        ``<Errors errorMessage="..."/>`` children on failure. We parse the XML first; a JSON
        fallback is retained defensively for legacy/sandbox shapes. Success REQUIRES a non-empty
        upload index — a 200 with no index is a failure, not a silent success.
        """
        xml_result = cls._parse_anaf_header(response.text or "")
        if xml_result is not None:
            return xml_result
        return cls._parse_json_fallback(response)

    @classmethod
    def _parse_anaf_header(cls, text: str) -> UploadResponse | None:
        """Parse the ANAF ``<header>`` XML; return None if the body is not that XML."""
        stripped = text.strip()
        if not stripped.startswith("<"):
            return None
        from lxml import etree  # noqa: PLC0415  # local import keeps lxml off the hot path

        try:
            root = etree.fromstring(stripped.encode("utf-8"))
        except (etree.XMLSyntaxError, ValueError):
            return None
        if etree.QName(root).localname != "header":
            return None

        exec_status = root.get("ExecutionStatus", "")
        upload_index = root.get("index_incarcare", "")
        errors = [
            (el.get("errorMessage") or "").strip()
            for el in root.iter()
            if etree.QName(el).localname == "Errors" and el.get("errorMessage")
        ]
        raw: dict[str, Any] = {
            "ExecutionStatus": exec_status,
            "index_incarcare": upload_index,
            "errors": errors,
            "raw_text": text,
        }
        # Success ONLY when ANAF accepted for processing (status 0) AND returned an index.
        if exec_status == "0" and upload_index:
            return cls(
                success=True,
                upload_index=upload_index,
                message="Upload accepted for processing",
                raw_response=raw,
            )
        if not errors:
            errors = [f"ANAF upload rejected (ExecutionStatus={exec_status!r}, no index_incarcare)"]
        return cls(success=False, message=errors[0], errors=errors, raw_response=raw)

    @classmethod
    def _parse_json_fallback(cls, response: requests.Response) -> UploadResponse:
        """Defensive JSON parsing for legacy/sandbox responses that are not the ANAF XML header."""
        try:
            data = response.json() if response.text else {}
        except json.JSONDecodeError:
            data = {"raw_text": response.text}

        upload_index = data.get("index_incarcare", "")
        if response.status_code == HTTPStatus.OK and upload_index:
            return cls(
                success=True,
                upload_index=upload_index,
                message=data.get("message", "Upload successful"),
                raw_response=data,
            )

        errors = data.get("errors", [])
        if isinstance(errors, str):
            errors = [errors]
        elif not errors and "message" in data:
            errors = [data["message"]]
        elif not errors:
            errors = [f"HTTP {response.status_code}: {(response.text or '')[:200]}"]

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
    errors: list[dict[str, Any]] = field(default_factory=list)
    raw_response: dict[str, Any] = field(default_factory=dict)

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
    def from_dict(cls, data: dict[str, Any]) -> MessageInfo:
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


def extract_zip_members(content: bytes) -> dict[str, bytes]:
    """Extract the members of an ANAF ``/descarcare`` ZIP.

    A successful download returns a ZIP containing the original invoice XML plus the Ministry of
    Finance electronic seal (``semnatura_*.xml``). Returns a ``{filename: bytes}`` map. This only
    READS the archive — persisting the sealed XML as the legal original (10-year archival) is
    tracked separately; do not add storage here (#123 plan, Phase 3).

    Raises:
        zipfile.BadZipFile: if ``content`` is not a valid ZIP.
    """
    import io  # noqa: PLC0415
    import zipfile  # noqa: PLC0415

    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def find_sealed_xml(members: dict[str, bytes]) -> bytes | None:
    """Return the ANAF-sealed invoice XML from extracted ZIP members, or None.

    Heuristic: the sealed original is the ``.xml`` member that is NOT the ``semnatura_*`` signature.
    """
    for name, data in members.items():
        lower = name.lower()
        if lower.endswith(".xml") and not lower.startswith("semnatura"):
            return data
    return None


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
    TOKEN_CACHE_KEY: ClassVar[str] = (
        "efactura_token_{env}"  # Not a real secret: cache key name  # noqa: S105  # Not a real secret: config key name
    )

    def __init__(self, config: EFacturaConfig | None = None):
        self.config = config or EFacturaConfig.from_settings()
        self._token: TokenResponse | None = None
        self._default_headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "PRAHO-EFactura/1.0",
        }

    def close(self) -> None:
        """No-op — safe_request() manages sessions internally."""

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
            # ANAF wants the JWT-format token; client auth is via Basic Auth, NOT a body secret.
            "token_content_type": "jwt",
        }

        try:
            response = safe_request(
                "POST",
                self.config.oauth_token_url,
                policy=EFACTURA_POLICY,
                data=data,
                headers={**self._default_headers, **self._oauth_client_auth_header()},
            )
            response.raise_for_status()
            token = TokenResponse.from_dict(response.json())
            self._cache_token(token)
            return token
        except requests.RequestException as e:
            logger.error(f"Token exchange failed: {e}")
            raise AuthenticationError(f"Failed to exchange code for token: {e}") from e

    def _oauth_client_auth_header(self) -> dict[str, str]:
        """HTTP Basic Auth header for OAuth client authentication.

        ANAF uses ``client_secret_basic``: client_id + client_secret are base64-encoded in the
        Authorization header, NOT sent in the form body. (Live-verify against the sandbox — the
        exact auth method is part of the credential-gated contract, #123 Gap 8.)
        """
        raw = f"{self.config.client_id}:{self.config.client_secret}".encode()
        return {"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"}

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
            "token_content_type": "jwt",
        }

        try:
            response = safe_request(
                "POST",
                self.config.oauth_token_url,
                policy=EFACTURA_POLICY,
                data=data,
                headers={**self._default_headers, **self._oauth_client_auth_header()},
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

        return self._post_upload("/upload", params, xml_content)

    def upload_b2c(
        self,
        xml_content: str,
        *,
        standard: str = "UBL",
        cif: str | None = None,
    ) -> UploadResponse:
        """Upload a B2C (consumer) invoice via ANAF's ``/uploadb2c`` endpoint.

        B2C e-invoicing has been mandatory since Jan 2025. The document is the same UBL, but the
        endpoint differs and the buyer is identified by CNP rather than a CUI. The buyer-side XML
        rules are live-contract sensitive (HIGHER risk) and MUST be confirmed against the ANAF
        sandbox before go-live; this method's request shape is contract-fixture verified only.
        """
        if not self.config.is_valid():
            return UploadResponse.error("Invalid e-Factura configuration")

        params: dict[str, str] = {
            "standard": standard,
            "cif": cif or self.config.company_cui,
        }
        return self._post_upload("/uploadb2c", params, xml_content)

    def _post_upload(self, endpoint_path: str, params: dict[str, str], xml_content: str) -> UploadResponse:
        """Shared POST for the B2B ``/upload`` and B2C ``/uploadb2c`` endpoints."""
        try:
            access_token = self._get_access_token()

            response = self._request_with_retry(
                "POST",
                f"{self.config.base_url}{endpoint_path}",
                params=params,
                data=xml_content.encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": self.config.upload_content_type,
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

            if response.status_code == HTTPStatus.OK:
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
                # ANAF endpoint is /listaMesajeFactura (the bare /listaMesaje 404s).
                f"{self.config.base_url}/listaMesajeFactura",
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

    def list_messages_paginated(
        self,
        start_ms: int,
        end_ms: int,
        page: int = 1,
        cif: str | None = None,
        filter_type: str | None = None,
    ) -> list[MessageInfo]:
        """List messages over an explicit time window using ANAF's paginated endpoint.

        ANAF's ``/listaMesajePaginatieFactura`` takes ``startTime``/``endTime`` as Unix epoch
        MILLISECONDS and a 1-based ``pagina``. Use this when the 60-day ``list_messages`` window
        is too coarse or when more than one page of results is expected.
        """
        params: dict[str, Any] = {
            "startTime": start_ms,
            "endTime": end_ms,
            "cif": cif or self.config.company_cui,
            "pagina": page,
        }
        if filter_type:
            params["filtru"] = filter_type

        try:
            access_token = self._get_access_token()

            response = self._request_with_retry(
                "GET",
                f"{self.config.base_url}/listaMesajePaginatieFactura",
                params=params,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            data = response.json() if response.text else {}
            messages = data.get("mesaje", data.get("messages", []))
            return [MessageInfo.from_dict(m) for m in messages]

        except AuthenticationError:
            raise
        except requests.RequestException as e:
            logger.error(f"e-Factura paginated list messages failed: {e}")
            raise NetworkError(f"Failed to list messages (paginated): {e}") from e

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

            if response.status_code == HTTPStatus.OK:
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
        """Make HTTP request with retry logic via safe_request()."""
        # Merge default headers with caller-provided headers
        merged_headers = {**self._default_headers, **kwargs.pop("headers", {})}
        last_error: Exception | None = None

        for attempt in range(self.config.max_retries):
            try:
                response = safe_request(method, url, policy=EFACTURA_POLICY, headers=merged_headers, **kwargs)

                # Check for rate limiting
                if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    retry_after = min(
                        int(response.headers.get("Retry-After", 60)),
                        MAX_RETRY_AFTER_SECONDS,
                    )
                    logger.warning(
                        f"⚠️ [e-Factura] Rate limited, waiting {retry_after}s (capped at {MAX_RETRY_AFTER_SECONDS}s)"
                    )
                    time.sleep(retry_after)
                    continue

                return response

            except requests.Timeout as e:
                last_error = e
                logger.warning(f"⚠️ [e-Factura] Request timeout (attempt {attempt + 1}/{self.config.max_retries})")
            except requests.ConnectionError as e:
                last_error = e
                logger.warning(f"⚠️ [e-Factura] Connection error (attempt {attempt + 1}/{self.config.max_retries})")

            # Wait before retry (exponential backoff)
            if attempt < self.config.max_retries - 1:
                delay = self.config.retry_delay * (2**attempt)
                time.sleep(delay)

        raise NetworkError(f"Request failed after {self.config.max_retries} attempts: {last_error}")
