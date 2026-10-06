"""Authentication backend that loads the session user together with its credential version."""

from __future__ import annotations

from django.contrib.auth.backends import ModelBackend

from .models import User


class CredentialVersionModelBackend(ModelBackend):
    """ModelBackend whose session-user lookup joins the credential version (#553).

    Django verifies the session hash on every authenticated request, and
    ``User._get_session_auth_hash`` reads ``credential_version``. Joining it into the
    user query removes a second SELECT per request. On the async path it also removes a
    lazy synchronous query, which raised SynchronousOnlyOperation.

    Only the lookup changes. Both methods keep ModelBackend's ``user_can_authenticate``
    check, so an inactive user still gets no session user.
    """

    def get_user(self, user_id: int | str) -> User | None:
        try:
            user = User._default_manager.select_related("credential_version").get(pk=user_id)
        except User.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None

    async def aget_user(self, user_id: int | str) -> User | None:
        try:
            user = await User._default_manager.select_related("credential_version").aget(pk=user_id)
        except User.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None
