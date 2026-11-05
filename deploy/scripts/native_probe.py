"""Non-business HTTPS/HMAC deployment probes. Never print response bodies or secrets."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit


def request(url: str, headers: dict[str, str], body: bytes = b"{}") -> tuple[int, object]:
    if not url.startswith("https://"):
        raise ValueError("Native peer probes require verified HTTPS")
    parsed = urlsplit(url)
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=15)
    try:
        if os.environ.get("NATIVE_PROBE_LOOPBACK") == "true":
            connection.sock = ssl.create_default_context().wrap_socket(
                socket.create_connection(("127.0.0.1", parsed.port or 443), timeout=15),
                server_hostname=parsed.hostname,
            )
        connection.request("POST", parsed.path, body=body, headers=headers)
        response = connection.getresponse()
        try:
            payload = json.loads(response.read(65536))
        except (ValueError, UnicodeError):
            payload = None
        return response.status, payload
    finally:
        connection.close()


def probe_api() -> None:
    url = os.environ["PLATFORM_API_BASE_URL"].rstrip("/") + "/localisation/"
    path = "/api/localisation/"
    for good, expected in ((True, 200), (False, 401)):
        portal = os.environ.get("PORTAL_ID", "portal-001")
        nonce, timestamp = secrets.token_urlsafe(32), str(int(time.time()))
        body = json.dumps({"timestamp": int(timestamp)}, separators=(",", ":")).encode()
        digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        canonical = "\n".join(("POST", path, "application/json", digest, portal, nonce, timestamp))
        secret = os.environ.get("PORTAL_HMAC_SECRET") or os.environ["PLATFORM_API_SECRET"]
        signature = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest() if good else "0" * 64
        status, payload = request(
            url,
            {
                "Content-Type": "application/json",
                "X-Portal-Id": portal,
                "X-Nonce": nonce,
                "X-Timestamp": timestamp,
                "X-Body-Hash": digest,
                "X-Signature": signature,
            },
            body,
        )
        if status != expected:
            raise ValueError(f"Portal API authentication probe expected {expected}, received {status}")
        if good and (not isinstance(payload, dict) or payload.get("success") is not True):
            raise ValueError("Portal API authentication probe returned an unexpected response shape")


def probe_callback() -> None:
    timestamp = str(int(time.time()))
    signature = hmac.new(
        os.environ["PLATFORM_TO_PORTAL_WEBHOOK_SECRET"].encode(), timestamp.encode() + b".{}", hashlib.sha256
    ).hexdigest()
    status, body = request(
        os.environ["PORTAL_PAYMENT_WEBHOOK_URL"],
        {
            "Content-Type": "application/json",
            "X-Platform-Timestamp": timestamp,
            "X-Platform-Signature": signature,
        },
    )
    if status != 400 or body != {"error": "order_id required"}:
        raise ValueError(f"Authenticated empty callback expected order validation with status 400, received {status}")


if __name__ == "__main__":
    try:
        {"api": probe_api, "callback": probe_callback}[sys.argv[1]]()
    except ssl.SSLError:
        print("Native peer TLS verification failed", file=sys.stderr)
        sys.exit(1)
    except OSError as error:
        print(f"Native peer connection failed (errno={error.errno})", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print("Native peer returned an invalid JSON response", file=sys.stderr)
        sys.exit(1)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyError, IndexError):
        print("Native peer authentication verification failed", file=sys.stderr)
        sys.exit(1)
