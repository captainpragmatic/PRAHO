"""The one check of a signed-in user's password: refused while locked, and a wrong one counts.

Login has its own path, which also reports the lockout and upgrades an outdated hash. Every other
password check a signed-in session can reach (enabling or disabling 2FA, new backup codes,
changing the password, on the API and on the staff pages) goes through ``check_password_locked``,
so a stolen session cannot guess the password faster than the account lockout allows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth.hashers import check_password

if TYPE_CHECKING:
    from .models import User


def check_password_locked(user: User, raw_password: str) -> bool:
    """Whether ``raw_password`` is the user's password, checked for a signed-in session.

    A locked account is refused without checking. A wrong password counts toward the lockout: the
    caller answers its refusal rather than raising inside its transaction, so the count commits.
    An empty password is refused without counting, as it guesses nothing.

    The stored hash is never upgraded here, unlike ``User.check_password``. Upgrading it moves the
    session hash, so a check that passed before a wrong code would end the session that made it;
    an outdated hash is upgraded at the next login instead. The caller resets the count once its
    whole proof has passed (``proof_passed``).
    """
    if user.is_account_locked():
        return False
    if not raw_password:
        return False
    if not check_password(raw_password, user.password):
        user.increment_failed_login_attempts()
        return False
    return True


def proof_passed(user: User) -> None:
    """Clear the failure count once the password and any second factor have both passed, as login does."""
    if user.failed_login_attempts or user.account_locked_until:
        user.reset_failed_login_attempts()
