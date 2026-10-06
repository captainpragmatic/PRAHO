"""Staff login for the dev QA sweeps, kept free of Django so tests can drive it against a live server."""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

import pyotp
import requests

_LOGIN = "/auth/login/"
_MFA_VERIFY = "/auth/mfa/verify/"
# A code submitted in the last seconds of its 30-second window can expire in flight.
_MIN_SECONDS_LEFT_IN_WINDOW = 3


class LoginFailedError(RuntimeError):
    """The sweep could not establish a staff session; nothing after this can be trusted."""


def page_token(session: requests.Session, base: str, path: str) -> str:
    html = session.get(f"{base}{path}").text
    match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', html)
    if not match:
        raise LoginFailedError(f"no CSRF token on {path}")
    return match.group(1)


def _post_form(session: requests.Session, base: str, path: str, data: dict[str, str]) -> requests.Response:
    return session.post(
        f"{base}{path}",
        data={**data, "csrfmiddlewaretoken": page_token(session, base, path)},
        headers={"Referer": f"{base}{path}"},
    )


def _submit_totp(session: requests.Session, base: str, secret: str) -> None:
    totp = pyotp.TOTP(secret)
    seconds_left = totp.interval - time.time() % totp.interval
    if seconds_left < _MIN_SECONDS_LEFT_IN_WINDOW:
        time.sleep(seconds_left + 0.5)
    _post_form(session, base, _MFA_VERIFY, {"token": totp.now()})


def login(session: requests.Session, base: str, email: str, password: str, totp_secret: str | None = None) -> None:
    """Establish a staff session, completing the second factor when the account has one.

    Raises LoginFailedError unless the session can open the settings page. That check must not follow
    redirects: an anonymous request for /settings/ redirects to the login page, which answers 200,
    so a redirect-following status check passes for every failed login.
    """
    response = _post_form(session, base, _LOGIN, {"email": email, "password": password})
    if urlparse(response.url).path == _MFA_VERIFY:
        if not totp_secret:
            raise LoginFailedError(
                f"{email} has two-factor authentication enrolled, so the login stopped at the second factor "
                "and no TOTP secret was given"
            )
        _submit_totp(session, base, totp_secret)

    check = session.get(f"{base}/settings/", allow_redirects=False)
    if check.status_code != 200:
        where = check.headers.get("Location", "")
        raise LoginFailedError(
            f"no staff session for {email}: /settings/ answered {check.status_code} {where}".rstrip()
            + ". If a TOTP code was submitted, a code already used in the last 30 seconds is refused as a"
            " replay; wait for the next one."
        )
