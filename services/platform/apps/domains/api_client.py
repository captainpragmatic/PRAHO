"""
Secure API Client for Domain Registrar Integration
Separated complex API call logic to reduce cyclomatic complexity.
"""

import logging
import secrets
import time
from typing import Any

import requests
from requests import Response

from .models import Registrar

logger = logging.getLogger(__name__)

# API security constants
API_REQUEST_TIMEOUT = 30  # seconds
API_MAX_RETRIES = 3
HTTP_SUCCESS_THRESHOLD = 400  # HTTP status codes below this are considered successful


class SecureAPIClient:
    """🔒 Secure HTTP API client with retry logic and security features"""

    @staticmethod
    def make_secure_request(
        registrar: Registrar, method: str, endpoint: str, data: dict[str, Any]
    ) -> tuple[bool, dict[str, Any]]:
        """🔒 Make secure HTTP API call with timeout and retry logic"""
        full_url = f"{registrar.api_endpoint.rstrip('/')}{endpoint}"
        api_key, api_secret = registrar.get_api_credentials()

        headers = SecureAPIClient._build_headers(api_key, api_secret)

        for attempt in range(API_MAX_RETRIES):
            try:
                logger.info(f"🌐 [API] {method} {endpoint} (attempt {attempt + 1}/{API_MAX_RETRIES})")

                response = SecureAPIClient._make_http_request(method, full_url, data, headers)

                # Handle successful response
                if response.status_code < HTTP_SUCCESS_THRESHOLD:
                    return SecureAPIClient._parse_success_response(response)

                # Handle failed response
                error_result = SecureAPIClient._handle_error_response(response, attempt)
                if error_result:
                    return False, error_result

            except requests.exceptions.Timeout:
                if SecureAPIClient._handle_timeout(registrar, attempt):
                    return False, {"error": "Request timeout"}

            except requests.exceptions.ConnectionError as e:
                if SecureAPIClient._handle_connection_error(registrar, attempt, e):
                    return False, {"error": "Connection failed"}

            except Exception as e:
                if SecureAPIClient._handle_unexpected_error(registrar, attempt, e):
                    return False, {"error": str(e)}

            # Wait before retry with secure jitter
            if attempt < API_MAX_RETRIES - 1:
                SecureAPIClient._secure_backoff(attempt)

        return False, {"error": "All retry attempts failed"}

    @staticmethod
    def _build_headers(api_key: str, api_secret: str) -> dict[str, str]:
        """🔑 Build secure request headers"""
        headers = {
            "User-Agent": "PRAHO-Platform/1.0",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }

        if api_secret:
            headers["X-API-Secret"] = api_secret

        return headers

    @staticmethod
    def _make_http_request(method: str, url: str, data: dict[str, Any], headers: dict[str, str]) -> Response:
        """🌐 Make HTTP request with security settings"""
        return requests.request(
            method=method,
            url=url,
            json=data,
            headers=headers,
            timeout=API_REQUEST_TIMEOUT,
            verify=True,  # Always verify SSL certificates
        )

    @staticmethod
    def _parse_success_response(response: Response) -> tuple[bool, dict[str, Any]]:
        """✅ Parse successful API response"""
        try:
            return True, response.json()
        except ValueError:
            return True, {"response": response.text}

    @staticmethod
    def _handle_error_response(response: Response, attempt: int) -> dict[str, Any] | None:
        """❌ Handle HTTP error response"""
        logger.warning(f"⚠️ [API] HTTP {response.status_code}: {response.text}")
        if attempt == API_MAX_RETRIES - 1:  # Last attempt
            return {
                "error": f"HTTP {response.status_code}",
                "message": response.text[:200],
            }
        return None

    @staticmethod
    def _handle_timeout(registrar: Registrar, attempt: int) -> bool:
        """⏱️ Handle request timeout"""
        logger.warning(f"⏱️ [API] Timeout for {registrar.name} (attempt {attempt + 1})")
        return attempt == API_MAX_RETRIES - 1

    @staticmethod
    def _handle_connection_error(registrar: Registrar, attempt: int, error: Exception) -> bool:
        """🔌 Handle connection error"""
        logger.warning(f"🔌 [API] Connection error for {registrar.name}: {error}")
        return attempt == API_MAX_RETRIES - 1

    @staticmethod
    def _handle_unexpected_error(registrar: Registrar, attempt: int, error: Exception) -> bool:
        """🔥 Handle unexpected error"""
        logger.error(f"🔥 [API] Unexpected error for {registrar.name}: {error}")
        return attempt == API_MAX_RETRIES - 1

    @staticmethod
    def _secure_backoff(attempt: int) -> None:
        """⏳ Secure exponential backoff with cryptographic jitter"""
        jitter = secrets.randbelow(1000) / 1000  # 0-1 second jitter
        delay = (2**attempt) + jitter
        time.sleep(delay)
