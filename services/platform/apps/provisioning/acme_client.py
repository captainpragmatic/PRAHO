"""The ACME protocol client behind account-name certificates (ADR-0061 P1.10).

The issuer (`account_name_certificates`) talks to the small `AcmeClient` protocol below; this module is
the one place that knows the `acme` library. Two things the library does not do for us live here:

* Every request goes through `safe_request` (DNS pinning, host allowlist), never a raw `requests` session.
* A `Retry-After` is carried to the caller. The library drops response headers when it raises a problem
  document, so the network layer reads them before that happens.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Protocol
from urllib.parse import urlsplit

import requests
from acme import challenges, messages
from acme import errors as acme_errors
from acme.client import ClientNetwork, ClientV2
from josepy.jwa import ES256
from josepy.jwk import JWK

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError, safe_request

logger = logging.getLogger(__name__)

DEFAULT_RATE_LIMIT_SECONDS = 3600.0
ORDER_DEADLINE_SECONDS = 180
_USER_AGENT = "praho-acme"
_HTTP_TOO_MANY_REQUESTS = 429
_HTTP_SERVICE_UNAVAILABLE = 503
_REQUEST_TIMEOUT_SECONDS = 30.0


class AcmeError(Exception):
    """An ACME exchange did not complete. ``retry_after_seconds`` is the server's Retry-After when it sent one."""

    def __init__(self, message: str, *, retry_after_seconds: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class AcmeRateLimited(AcmeError):  # noqa: N818  # Reads as the condition, like the ACME problem type it mirrors
    """The server refused the request for rate: nothing was ordered, ask again after the delay."""


class AcmeTransientError(AcmeError):
    """A network or server failure: the order, if there is one, is still good and can be resumed."""


class AcmeOrderFailed(AcmeError):  # noqa: N818  # Reads as the condition
    """The server rejected the order or a challenge; this order will not become a certificate."""


@dataclass(frozen=True)
class Dns01Challenge:
    """A TXT value that must exist at ``name`` for the server to validate the order."""

    name: str
    value: str
    handle: Any = None  # the client's own object for this challenge


@dataclass(frozen=True)
class AcmeOrder:
    """An order at the ACME server and the challenges still to answer."""

    url: str
    challenges: tuple[Dns01Challenge, ...]
    handle: Any = None  # the client's own object for this order


class AcmeClient(Protocol):
    """What the issuer needs from an ACME server. Tests supply a fake directory behind this."""

    def place_order(self, csr_pem: bytes) -> AcmeOrder:
        """Create an order for the names in the CSR."""

    def load_order(self, url: str, csr_pem: bytes) -> AcmeOrder:
        """Read an order placed earlier, so a crashed attempt resumes it instead of ordering again."""

    def complete(self, order: AcmeOrder) -> bytes:
        """Answer the challenges (their TXT values are published), wait, finalise, return the full chain as PEM."""


def retry_after_seconds(response: requests.Response) -> float | None:
    """The Retry-After header as seconds (delta-seconds or HTTP-date), or None when absent or invalid."""
    raw = (response.headers.get("Retry-After") or "").strip()
    if not raw:
        return None
    if raw.isdigit():
        return float(raw)
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.UTC)
    return max(0.0, (when - dt.datetime.now(dt.UTC)).total_seconds())


class SafeAcmeNetwork(ClientNetwork):
    """The library's signing network layer, sending through `safe_request` and surfacing Retry-After."""

    def __init__(self, key: JWK, policy: OutboundPolicy) -> None:
        super().__init__(key, alg=ES256, user_agent=_USER_AGENT)
        self._policy = policy

    def _send_request(self, method: str, url: str, *args: Any, **kwargs: Any) -> requests.Response:
        headers = dict(kwargs.get("headers") or {})
        headers.setdefault("User-Agent", self.user_agent)
        response = safe_request(method, url, policy=self._policy, headers=headers, data=kwargs.get("data"))
        response.encoding = "utf-8"
        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            raise AcmeRateLimited(
                f"ACME server rate limit on {method} {urlsplit(url).path}",
                retry_after_seconds=retry_after_seconds(response) or DEFAULT_RATE_LIMIT_SECONDS,
            )
        if response.status_code == _HTTP_SERVICE_UNAVAILABLE:
            raise AcmeTransientError(
                f"ACME server unavailable on {method} {urlsplit(url).path}",
                retry_after_seconds=retry_after_seconds(response),
            )
        return response


@contextmanager
def _translating() -> Iterator[None]:
    """Turn the library's and the transport's exceptions into the three the issuer decides on."""
    try:
        yield
    except AcmeError:
        raise
    except messages.Error as exc:
        if exc.code == "rateLimited":
            raise AcmeRateLimited(str(exc), retry_after_seconds=DEFAULT_RATE_LIMIT_SECONDS) from exc
        if exc.code in {"serverInternal", "badNonce"}:
            raise AcmeTransientError(str(exc)) from exc
        raise AcmeOrderFailed(str(exc)) from exc
    except (acme_errors.ValidationError, acme_errors.IssuanceError) as exc:
        raise AcmeOrderFailed(str(exc)) from exc
    except (acme_errors.Error, requests.RequestException, OutboundSecurityError) as exc:
        raise AcmeTransientError(f"{type(exc).__name__}: {exc}") from exc


class LibraryAcmeClient:
    """`AcmeClient` over the `acme` library, with one ACME account per key."""

    def __init__(self, directory_url: str, account_key_pem: str) -> None:
        host = urlsplit(directory_url).hostname or ""
        policy = OutboundPolicy(
            name="acme",
            allowed_domains=frozenset({host}),
            timeout_seconds=_REQUEST_TIMEOUT_SECONDS,
            max_retries=0,
            retry_connection_errors=False,
        )
        self._key = JWK.load(account_key_pem.encode())
        self._net = SafeAcmeNetwork(self._key, policy)
        with _translating():
            directory = ClientV2.get_directory(directory_url, self._net)
            self._client = ClientV2(directory, self._net)
            self._register()

    def _register(self) -> None:
        """Create the account for this key, or adopt the one the server already has for it."""
        try:
            self._client.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
        except acme_errors.ConflictError as exc:
            self._net.account = messages.RegistrationResource(body=messages.Registration(), uri=exc.location)

    def place_order(self, csr_pem: bytes) -> AcmeOrder:
        with _translating():
            orderr = self._client.new_order(csr_pem)
        return self._wrap(str(orderr.uri), list(orderr.authorizations), orderr)

    def load_order(self, url: str, csr_pem: bytes) -> AcmeOrder:
        with _translating():
            # The library has no public "order by URL"; a POST-as-GET of the stored URL is the protocol's way.
            body = messages.Order.from_json(self._client._post_as_get(url).json())
            authzrs = [
                self._client._authzr_from_response(self._client._post_as_get(auth_url), uri=auth_url)
                for auth_url in body.authorizations
            ]
        orderr = messages.OrderResource(body=body, uri=url, authorizations=authzrs, csr_pem=csr_pem)
        return self._wrap(url, authzrs, orderr)

    def _wrap(self, url: str, authzrs: list[Any], orderr: Any) -> AcmeOrder:
        pending = [
            Dns01Challenge(
                name=challb.chall.validation_domain_name(authzr.body.identifier.value),
                value=challb.chall.validation(self._key),
                handle=challb,
            )
            for authzr in authzrs
            if authzr.body.status == messages.STATUS_PENDING
            for challb in authzr.body.challenges
            if isinstance(challb.chall, challenges.DNS01)
        ]
        return AcmeOrder(url=url, challenges=tuple(pending), handle=orderr)

    def complete(self, order: AcmeOrder) -> bytes:
        # The library compares this deadline with naive local times, so it cannot be timezone-aware.
        deadline = dt.datetime.now() + dt.timedelta(
            seconds=ORDER_DEADLINE_SECONDS
        )  # The library compares naive local times
        with _translating():
            for challenge in order.challenges:
                self._client.answer_challenge(challenge.handle, challenge.handle.chall.response(self._key))
            orderr = self._client.poll_authorizations(order.handle, deadline)
            orderr = self._client.finalize_order(orderr, deadline)
        return str(orderr.fullchain_pem).encode()
