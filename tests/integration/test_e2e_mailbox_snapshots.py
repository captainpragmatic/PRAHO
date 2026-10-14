"""The e2e mailbox helper finds every delivered mail, however Django filed it (#689).

test_signup_form_password_validation failed once in eight full e2e runs, on the mail queue.
Django's file mail backend names its file once per backend instance from the time and the
instance's id(), and appends to it. One task run sends several mails; when two backends are
made in the same second and the second reuses the first one's memory, both mails land in one
file. The helper read each new file as a single message and ignored files that already
existed, so the second recipient's mail was never found.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from django.core.mail import EmailMessage
from django.core.mail.backends.filebased import EmailBackend

from tests.e2e.helpers import registration


def _send(backend: EmailBackend, to: str) -> None:
    backend.send_messages([EmailMessage(subject="Confirm", body=f"Hello {to}", to=[to])])


@pytest.fixture
def mail_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(registration, "MAIL_DIRECTORY", tmp_path)
    return tmp_path


def test_two_mails_in_one_new_file_are_both_found(mail_directory: Path) -> None:
    before = registration.mailbox()
    backend = EmailBackend(file_path=str(mail_directory))  # one instance, one file, as with a reused id()
    _send(backend, "first@e2e.test")
    _send(backend, "second@e2e.test")

    assert len(list(mail_directory.glob("*.log"))) == 1
    assert [m["To"] for m in registration.delivered_to("first@e2e.test", before)] == ["first@e2e.test"]
    assert [m["To"] for m in registration.delivered_to("second@e2e.test", before)] == ["second@e2e.test"]


def test_a_mail_appended_to_a_file_that_existed_before_is_found(mail_directory: Path) -> None:
    backend = EmailBackend(file_path=str(mail_directory))
    _send(backend, "earlier@e2e.test")
    before = registration.mailbox()
    _send(backend, "later@e2e.test")

    assert [m["To"] for m in registration.delivered_to("later@e2e.test", before)] == ["later@e2e.test"]
    # Mail delivered before the snapshot is not reported again.
    assert registration.delivered_to("earlier@e2e.test", before) == []
