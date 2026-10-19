"""A fake ACME directory for the account-name certificate tests.

It stands behind the `AcmeClient` protocol, so the issuer's own logic runs for real while nothing
reaches Let's Encrypt. Like the real server it will only issue when the challenge value is published
as a TXT record owned by the order, which it checks in the faked Cloudflare store.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from apps.provisioning.account_name_certificates import order_owner_tag
from apps.provisioning.acme_client import AcmeOrder, AcmeOrderFailed, AcmeRateLimited, Dns01Challenge


class SimulatedCrash(BaseException):  # Like a killed worker: not an Exception, so no handler may swallow it
    """Raised by the fake to stand for the process dying mid-order."""


def issue_chain(csr_pem: bytes, lifetime_days: int) -> str:
    """A leaf for the CSR's key and names, signed by a throwaway CA, as full-chain PEM."""
    csr = x509.load_pem_x509_csr(csr_pem)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake CA")])
    now = datetime.now(UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(ca_key, hashes.SHA256())
    )
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    leaf = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_name)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=lifetime_days))
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (leaf.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM)).decode()


class FakeAcme:
    """An ACME directory that counts what is asked of it and can be scripted to misbehave."""

    def __init__(self, cloudflare: Any, *, lifetime_days: int = 90) -> None:
        self.cloudflare = cloudflare
        self.lifetime_days = lifetime_days
        self.place_calls = 0
        self.load_calls = 0
        self.complete_calls = 0
        self.directory_urls: list[str] = []
        self.account_keys: list[str] = []
        self.rate_limit_seconds: float | None = None
        self.crash_in_complete = False
        self.reject_orders = False
        self._lock = threading.Lock()
        self._orders: dict[str, tuple[str, ...]] = {}
        self.csrs: dict[str, bytes] = {}

    # The factory the issuer calls; tests patch `build_acme_client` with this.
    def __call__(self, directory_url: str, account_key_pem: str) -> FakeAcme:
        self.directory_urls.append(directory_url)
        self.account_keys.append(account_key_pem)
        return self

    def _order(self, url: str, names: tuple[str, ...]) -> AcmeOrder:
        challenges = tuple(Dns01Challenge(name=f"_acme-challenge.{n}", value=f"proof-{url[-3:]}-{n}") for n in names)
        return AcmeOrder(url=url, challenges=challenges)

    def place_order(self, csr_pem: bytes) -> AcmeOrder:
        if self.rate_limit_seconds is not None:
            raise AcmeRateLimited("too many", retry_after_seconds=self.rate_limit_seconds)
        csr = x509.load_pem_x509_csr(csr_pem)
        names = tuple(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        )
        with self._lock:
            self.place_calls += 1
            url = f"https://acme.test/order/{self.place_calls:03d}"
            self._orders[url] = names
            self.csrs[url] = csr_pem
        return self._order(url, names)

    def load_order(self, url: str, csr_pem: bytes) -> AcmeOrder:
        with self._lock:
            self.load_calls += 1
            names = self._orders[url]
            self.csrs[url] = csr_pem
        return self._order(url, names)

    def complete(self, order: AcmeOrder) -> bytes:
        with self._lock:
            self.complete_calls += 1
        if self.crash_in_complete:
            self.crash_in_complete = False
            raise SimulatedCrash
        if self.reject_orders:
            raise AcmeOrderFailed("dns-01 validation failed")
        tag = order_owner_tag(order.url)
        for challenge in order.challenges:
            published = [
                r
                for r in list(self.cloudflare.store.values())
                if r["type"] == "TXT"
                and r["name"] == challenge.name
                and str(r["content"]).strip('"') == challenge.value
                and r.get("comment") == tag
            ]
            if not published:
                raise AcmeOrderFailed(f"no TXT value {challenge.value} owned by {tag} at {challenge.name}")
        return issue_chain(self.csrs[order.url], self.lifetime_days).encode()
