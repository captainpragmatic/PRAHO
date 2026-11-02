"""Copied into the disposable source to prove actual SMTP, IMAP, DNS and Unix identity."""

from __future__ import annotations

import hashlib
import imaplib
import smtplib
import ssl
import subprocess
import time
from uuid import uuid4


def unix_identity(owner: str) -> str:
    account = subprocess.check_output(["/usr/bin/getent", "passwd", owner])  # noqa: S603 -- fixture-owned exact native username
    shadow = subprocess.check_output(["/usr/bin/getent", "shadow", owner])  # noqa: S603 -- fixture-owned exact native username
    return hashlib.sha256(account + shadow).hexdigest()


def assert_retained_services(owner: str, domain: str, password: str, identity: str) -> None:
    token = "praho-component-" + uuid4().hex
    client = imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=ssl._create_unverified_context())  # noqa: S323 -- local native fixture certificate only
    try:
        client.login(owner, password)
        with smtplib.SMTP("127.0.0.1", 25, timeout=10) as smtp:
            assert (
                smtp.sendmail(
                    "fixture@" + domain,
                    owner + "@" + domain,
                    "From: fixture@"
                    + domain
                    + "\r\nTo: "
                    + owner
                    + "@"
                    + domain
                    + "\r\nSubject: "
                    + token
                    + "\r\n\r\nRetained component fixture.\r\n",
                )
                == {}
            )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert client.select("INBOX")[0] == "OK"
            status, found = client.search(None, "SUBJECT", token)
            assert status == "OK"
            if found[0]:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("Native SMTP delivery did not reach the retained mailbox")
        status, body = client.fetch(found[0].split()[-1], "(RFC822)")
        assert status == "OK"
        assert any(isinstance(item, tuple) and b"Retained component fixture." in item[1] for item in body)
    finally:
        client.logout()
    for kind in ("SOA", "MX", "A"):
        assert subprocess.check_output(["dig", "@127.0.0.1", "+short", domain, kind]).strip()  # noqa: S603, S607 -- exact owned fixture domain, read-only native DNS
    assert unix_identity(owner) == identity, "The retained Unix identity or authentication changed"
