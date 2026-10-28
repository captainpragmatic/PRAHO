"""Signed SNS envelopes for the SES webhook tests.

The canonical string is built here, with its own field order, and never by the production
builder. A test that signed with production code would pass for any canonicalisation, which
is exactly the property the verifier exists to enforce. The throwaway RSA key and the
self-signed certificate are generated once per process.
"""

from __future__ import annotations

import base64
import functools
import json
from unittest.mock import MagicMock
from uuid import uuid4

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tests.infrastructure.test_ssl_trust_reporting import _make_cert

TOPIC_ARN = "arn:aws:sns:eu-west-1:123456789012:ses-events"
OTHER_TOPIC_ARN = "arn:aws:sns:eu-west-1:999999999999:someone-elses-topic"
CERT_URL = "https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-0123456789abcdef.pem"
SUBSCRIBE_URL = "https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription&Token=fixture-token"
TOKEN = "fixture-token"  # noqa: S105  # public SNS token fixture, not a credential

NOTIFICATION = "Notification"
SUBSCRIPTION = "SubscriptionConfirmation"
UNSUBSCRIPTION = "UnsubscribeConfirmation"
ALL_TYPES = (NOTIFICATION, SUBSCRIPTION, UNSUBSCRIPTION)

# The AWS-documented signing order, written out here on purpose.
_NOTIFICATION_ORDER = ("Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type")
_CONFIRMATION_ORDER = ("Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type")
SIGNED_ORDER = {
    NOTIFICATION: _NOTIFICATION_ORDER,
    SUBSCRIPTION: _CONFIRMATION_ORDER,
    UNSUBSCRIPTION: _CONFIRMATION_ORDER,
}
REQUIRED_FIELDS = {
    NOTIFICATION: ("Message", "MessageId", "Timestamp", "TopicArn", "Type"),
    SUBSCRIPTION: _CONFIRMATION_ORDER,
    UNSUBSCRIPTION: _CONFIRMATION_ORDER,
}


@functools.cache
def signing_material() -> tuple[bytes, rsa.RSAPrivateKey]:
    """Return (certificate PEM, private key) for the throwaway SNS signer."""
    cert_pem, _key_pem, _cert, key = _make_cert("sns.eu-west-1.amazonaws.com")
    return cert_pem, key


def ses_event(kind: str = "Delivery", recipient: str = "victim@example.com") -> dict[str, object]:
    mail = {"messageId": "0000018f-aaaa-bbbb-cccc-000000000001"}
    if kind == "Bounce":
        return {
            "notificationType": "Bounce",
            "bounce": {
                "bounceType": "Permanent",
                "bouncedRecipients": [{"emailAddress": recipient}],
            },
            "mail": mail,
        }
    if kind == "Complaint":
        return {
            "notificationType": "Complaint",
            "complaint": {"complainedRecipients": [{"emailAddress": recipient}]},
            "mail": mail,
        }
    return {"notificationType": "Delivery", "mail": mail, "delivery": {"recipients": [recipient]}}


def envelope(kind: str = NOTIFICATION, **overrides: object) -> dict[str, object]:
    """An unsigned, structurally valid SNS envelope; ``overrides`` replace or add fields."""
    base: dict[str, object] = {
        "Type": kind,
        "MessageId": str(uuid4()),
        "TopicArn": TOPIC_ARN,
        "Timestamp": "2026-10-28T10:00:00.000Z",
    }
    if kind == NOTIFICATION:
        base["Subject"] = "Amazon SES Email Event Notification"
        base["Message"] = json.dumps(ses_event("Bounce"))
    else:
        base["Message"] = "You have chosen to subscribe to the topic. To confirm, visit the SubscribeURL."
        base["SubscribeURL"] = SUBSCRIBE_URL
        base["Token"] = TOKEN
    base.update(overrides)
    return base


def canonical(fields: dict[str, object]) -> bytes:
    declared = fields.get("Type")
    order = SIGNED_ORDER[declared] if isinstance(declared, str) and declared in SIGNED_ORDER else _NOTIFICATION_ORDER
    return "".join(f"{name}\n{fields[name]}\n" for name in order if name in fields).encode()


def sign(
    fields: dict[str, object],
    *,
    version: str = "1",
    algorithm: hashes.HashAlgorithm | None = None,
    sign_over: dict[str, object] | None = None,
    cert_url: str = CERT_URL,
) -> dict[str, object]:
    """Return ``fields`` plus a genuine signature. ``sign_over`` signs a different envelope."""
    _cert_pem, key = signing_material()
    if algorithm is None:
        algorithm = hashes.SHA256() if version == "2" else hashes.SHA1()  # noqa: S303  # nosec B303  # nosemgrep: insecure-hash-algorithm-sha1
    signed = sign_over if sign_over is not None else fields
    signature = key.sign(canonical(signed), padding.PKCS1v15(), algorithm)
    return {
        **fields,
        "SignatureVersion": version,
        "SigningCertURL": cert_url,
        "Signature": base64.b64encode(signature).decode(),
    }


def signed(kind: str = NOTIFICATION, **overrides: object) -> dict[str, object]:
    return sign(envelope(kind, **overrides))


class FakeNetwork:
    """Stand-in for ``safe_request`` that answers the certificate fetch and the confirmation GET."""

    def __init__(
        self,
        *,
        cert_status: int = 200,
        cert_body: bytes | None = None,
        cert_error: Exception | None = None,
        confirm_status: int = 200,
        confirm_error: Exception | None = None,
    ) -> None:
        self.cert_status = cert_status
        self.cert_body = cert_body if cert_body is not None else signing_material()[0]
        self.cert_error = cert_error
        self.confirm_status = confirm_status
        self.confirm_error = confirm_error
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __call__(self, method: str, url: str, **kwargs: object) -> MagicMock:
        self.calls.append((url, kwargs))
        if url.endswith(".pem"):
            if self.cert_error is not None:
                raise self.cert_error
            return MagicMock(status_code=self.cert_status, content=self.cert_body)
        if self.confirm_error is not None:
            raise self.confirm_error
        return MagicMock(status_code=self.confirm_status, content=b"")

    @property
    def cert_fetches(self) -> list[str]:
        return [url for url, _ in self.calls if url.endswith(".pem")]

    @property
    def confirmation_fetches(self) -> list[tuple[str, dict[str, object]]]:
        return [(url, kwargs) for url, kwargs in self.calls if not url.endswith(".pem")]
