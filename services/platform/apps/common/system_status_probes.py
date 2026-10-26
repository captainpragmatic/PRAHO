"""Read-only provider probes, isolated from the web process by a hard deadline.

The child receives effective credentials through stdin and returns only a fixed code.
It deliberately does not initialize Django, send mail, refresh OAuth or alter SDK globals.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from http import HTTPStatus
from pathlib import Path
from typing import cast
from urllib.parse import quote, urlsplit

from apps.common.outbound_http import OutboundPolicy, safe_request

MAX_RESPONSE_BYTES = 256 * 1024
PROVIDER_TIMEOUT = 5.0
TOTAL_TIMEOUT = 20.0


class ProbeCode(StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    INVALID_RESPONSE = "invalid_response"
    TOO_LARGE = "too_large"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    PERMISSION = "permission"
    THROTTLED = "throttled"
    DISABLED = "disabled"
    SANDBOX = "sandbox"
    UNVERIFIED = "unverified"


@dataclass
class ProbeBudget:
    """One budget shared by every external check in a refresh."""

    deadline: float = field(default_factory=lambda: time.monotonic() + TOTAL_TIMEOUT)

    @property
    def remaining(self) -> float:
        return min(PROVIDER_TIMEOUT, self.deadline - time.monotonic())

    def run(self, provider: str, config: dict[str, object]) -> ProbeCode:
        remaining = self.remaining
        if remaining <= 0:
            return ProbeCode.TIMEOUT
        # No shell, secrets in argv, inherited Django initialization, or daemon-worker
        # multiprocessing restrictions. The parent always reaps the child after killing it.
        try:
            payload = json.dumps({"provider": provider, "config": config})
            with subprocess.Popen(  # noqa: S603  # Fixed interpreter/module; private configuration goes only to stdin.
                [sys.executable, "-m", "apps.common.system_status_probes"],
                cwd=Path(__file__).resolve().parents[2],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            ) as process:
                try:
                    output, _ = process.communicate(payload, timeout=max(0.001, self.remaining))
                except subprocess.TimeoutExpired:
                    # AWS profiles may use credential_process. Kill descendants too,
                    # including any process that inherited our stdout pipe.
                    with suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                    return ProbeCode.TIMEOUT
                if process.returncode != 0:
                    return ProbeCode.UNAVAILABLE
                return ProbeCode(output.strip())
        except (OSError, ValueError, TypeError):
            return ProbeCode.UNAVAILABLE


def _read_response(response: object, provider: str = "") -> dict[str, object] | ProbeCode:
    """Bound decoded bytes while streaming, including compressed/lengthless responses."""
    import requests  # noqa: PLC0415

    response = cast(requests.Response, response)
    with response:
        body = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                return ProbeCode.TOO_LARGE
            body.extend(chunk)
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            data = {}
        if response.status_code != HTTPStatus.OK:
            if response.status_code == HTTPStatus.FORBIDDEN and _explicit_permission_denial(provider, data):
                return ProbeCode.PERMISSION
            failures: dict[int, ProbeCode] = {
                HTTPStatus.UNAUTHORIZED: ProbeCode.UNAUTHORIZED,
                HTTPStatus.TOO_MANY_REQUESTS: ProbeCode.THROTTLED,
                HTTPStatus.FORBIDDEN: ProbeCode.FORBIDDEN,
            }
            return failures.get(response.status_code, ProbeCode.UNAVAILABLE)
        if not isinstance(data, dict) or not data:
            return ProbeCode.INVALID_RESPONSE
        return cast(dict[str, object], data)


def _explicit_permission_denial(provider: str, data: object) -> bool:
    if not isinstance(data, dict):
        return False
    if provider == "ses":
        return data.get("__type") == "AccessDeniedException"
    error = data.get("error")
    return provider == "stripe" and isinstance(error, dict) and error.get("code") == "permission_missing"


def _http(provider: str, config: dict[str, object]) -> ProbeCode:
    hosts = {
        "sendgrid": frozenset({"api.sendgrid.com", "api.eu.sendgrid.com"}),
        "mailgun": frozenset({"api.mailgun.net", "api.eu.mailgun.net"}),
        "stripe": frozenset({"api.stripe.com"}),
        "efactura": frozenset({"api.anaf.ro"}),
        "ses": frozenset({str(config.get("host", ""))}),
    }
    url = str(config["url"])
    # Exact host comparison in addition to safe_request's suffix/DNS/HTTPS guard.
    if urlsplit(url).hostname not in hosts[provider]:
        return ProbeCode.UNVERIFIED
    response = safe_request(
        "GET",
        url,
        policy=OutboundPolicy(
            name="system_status",
            allowed_domains=hosts[provider],
            allowed_ports=frozenset({443}),
            connect_timeout_seconds=2,
            timeout_seconds=3,
            retry_connection_errors=False,
        ),
        headers=config.get("headers", {}),
        params=config.get("params", {}),
        stream=True,
    )
    data = _read_response(response, provider)
    if isinstance(data, ProbeCode):
        return data
    validators = {
        "sendgrid": _sendgrid_result,
        "mailgun": _mailgun_result,
        "ses": _ses_result,
        "stripe": _stripe_result,
        "efactura": _efactura_result,
    }
    return validators[provider](data)


def _sendgrid_result(data: dict[str, object]) -> ProbeCode:
    scopes = data.get("scopes")
    if not isinstance(scopes, list):
        return ProbeCode.INVALID_RESPONSE
    return ProbeCode.OK if "mail.send" in scopes else ProbeCode.PERMISSION


def _mailgun_result(data: dict[str, object]) -> ProbeCode:
    domain = data.get("domain")
    if not isinstance(domain, dict) or "state" not in domain:
        return ProbeCode.INVALID_RESPONSE
    return ProbeCode.OK if domain["state"] == "active" else ProbeCode.DISABLED


def _ses_result(data: dict[str, object]) -> ProbeCode:
    if not isinstance(data.get("SendingEnabled"), bool):
        return ProbeCode.INVALID_RESPONSE
    if not data["SendingEnabled"]:
        return ProbeCode.DISABLED
    return ProbeCode.OK if data.get("ProductionAccessEnabled") is True else ProbeCode.SANDBOX


def _stripe_result(data: dict[str, object]) -> ProbeCode:
    if data.get("object") != "account" or not isinstance(data.get("id"), str):
        return ProbeCode.INVALID_RESPONSE
    return ProbeCode.OK if data.get("charges_enabled") is True else ProbeCode.DISABLED


def _efactura_result(data: dict[str, object]) -> ProbeCode:
    # ANAF can return HTTP 200 with an error object. Missing 'mesaje' is NOT an empty inbox.
    # Exact benign example from https://mfinante.gov.ro/static/10/eFactura/listamesaje.html.
    if data == {"eroare": "Nu exista mesaje in intervalul selectat", "titlu": "Lista Mesaje"}:
        return ProbeCode.OK
    if any(key in data for key in ("eroare", "error", "errors")):
        return ProbeCode.INVALID_RESPONSE
    messages = data.get("mesaje", data.get("messages"))
    return ProbeCode.OK if isinstance(messages, list) else ProbeCode.INVALID_RESPONSE


def _smtp(config: dict[str, object]) -> ProbeCode:
    from django.conf import settings  # noqa: PLC0415
    from django.core.mail.backends.smtp import EmailBackend  # noqa: PLC0415

    if not settings.configured:
        settings.configure()
    with EmailBackend(**config, timeout=3, fail_silently=False) as backend:
        return ProbeCode.OK if backend.connection else ProbeCode.UNAVAILABLE


def _ses(config: dict[str, object]) -> ProbeCode:
    import boto3  # noqa: PLC0415
    from botocore.auth import SigV4Auth  # noqa: PLC0415
    from botocore.awsrequest import AWSRequest  # noqa: PLC0415
    from botocore.credentials import Credentials  # noqa: PLC0415

    session = boto3.session.Session(**cast(dict[str, object], config["session_params"]))
    client = cast(dict[str, object], config["client_params"])
    region = str(client.get("region_name") or session.region_name or "")
    if not region or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in region):
        return ProbeCode.UNVERIFIED
    host = f"email.{region}.amazonaws.com"
    endpoint = str(client.get("endpoint_url") or f"https://{host}")
    if endpoint.rstrip("/") != f"https://{host}":
        return ProbeCode.UNVERIFIED
    credentials = (
        Credentials(client["aws_access_key_id"], client["aws_secret_access_key"], client.get("aws_session_token"))
        if client.get("aws_access_key_id") and client.get("aws_secret_access_key")
        else session.get_credentials()
    )
    if credentials is None:
        return ProbeCode.UNAUTHORIZED
    request = AWSRequest(method="GET", url=f"{endpoint.rstrip('/')}/v2/email/account")
    SigV4Auth(credentials.get_frozen_credentials(), "ses", region).add_auth(request)
    return _http("ses", {"host": host, "url": request.url, "headers": dict(request.headers)})


def run_probe(provider: str, config: dict[str, object]) -> ProbeCode:
    """Keep every exception private. Results contain no provider-controlled text."""
    try:
        if provider == "smtp":
            return _smtp(config)
        if provider == "ses":
            return _ses(config)
        if provider in {"sendgrid", "mailgun", "stripe", "efactura"}:
            return _http(provider, config)
        return ProbeCode.UNVERIFIED
    except Exception:  # Probe boundary: no exception/credentials may cross into logs or UI.
        return ProbeCode.UNAVAILABLE


def email_probe_config() -> tuple[str, dict[str, object]]:
    """Resolve the real Anymail/SMTP backend without opening a connection."""
    import base64  # noqa: PLC0415

    from django.conf import settings  # noqa: PLC0415
    from django.core.mail import get_connection  # noqa: PLC0415

    backend_name = settings.EMAIL_BACKEND
    backend = get_connection(fail_silently=False)
    if backend_name == "django.core.mail.backends.smtp.EmailBackend":
        return "smtp", {
            "host": backend.host,
            "port": backend.port,
            "username": backend.username,
            "password": backend.password,
            "use_tls": backend.use_tls,
            "use_ssl": backend.use_ssl,
            "ssl_keyfile": backend.ssl_keyfile,
            "ssl_certfile": backend.ssl_certfile,
        }
    if backend_name == "anymail.backends.sendgrid.EmailBackend":
        return "sendgrid", {
            "url": backend.api_url + "scopes",
            "headers": {"Authorization": f"Bearer {backend.api_key}"},
        }
    if backend_name == "anymail.backends.mailgun.EmailBackend":
        domain = backend.sender_domain
        if not domain:
            from email.utils import parseaddr  # noqa: PLC0415

            domain = parseaddr(settings.DEFAULT_FROM_EMAIL)[1].rpartition("@")[2]
        if not domain:
            raise ValueError("Missing sender domain")
        auth = base64.b64encode(f"api:{backend.api_key}".encode()).decode()
        origin = urlsplit(backend.api_url)
        return "mailgun", {
            "url": f"{origin.scheme}://{origin.netloc}/v4/domains/{quote(domain, safe='')}",
            "headers": {"Authorization": f"Basic {auth}"},
        }
    if backend_name == "anymail.backends.amazon_ses.EmailBackend":
        client_params = {k: v for k, v in backend.client_params.items() if k != "config"}
        if not client_params.get("region_name"):
            client_params["region_name"] = backend.client_params["config"].region_name
        return "ses", {
            "session_params": backend.session_params,
            "client_params": client_params,
        }
    return "unsupported", {}


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    try:
        payload = json.load(sys.stdin)
        result = run_probe(payload["provider"], payload["config"])
    except Exception:  # Malformed private protocol must also produce only a fixed code.
        result = ProbeCode.UNAVAILABLE
    sys.stdout.write(result.value)
