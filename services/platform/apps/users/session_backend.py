"""Database sessions with an atomic per-user revocation index."""

from asgiref.sync import sync_to_async
from django.contrib.sessions.backends.db import SessionStore as DatabaseSessionStore
from django.contrib.sessions.models import Session
from django.db import transaction
from django.utils import timezone

from .models import UserSession


class SessionStore(DatabaseSessionStore):
    """Keep the index in sync with every persisted authentication session."""

    def save(self, must_create: bool = False) -> None:
        with transaction.atomic():
            super().save(must_create=must_create)
            # Read the user only after saving: reading first can trigger load(), which on
            # a miss replaces the key the store has just generated.
            key = self.session_key
            if key is None:  # save() always sets the key; this only narrows the type
                return
            user_id = self.get("_auth_user_id")
            if user_id is None:
                UserSession.objects.filter(session_key=key).delete()
                return
            # One statement and no read on every request: a key's user never changes,
            # because a login as someone else flushes the session and gets a new key, so
            # a conflict means the row is already right.
            UserSession.objects.bulk_create([UserSession(user_id=user_id, session_key=key)], ignore_conflicts=True)

    def delete(self, session_key: str | None = None) -> None:
        key = session_key or self.session_key
        with transaction.atomic():
            # cycle_key() has already saved the new key when it deletes the old one.
            UserSession.objects.filter(session_key=key).delete()
            super().delete(session_key)

    @classmethod
    def clear_expired(cls) -> None:
        """Remove expired sessions together with their index rows, so the index never outlives them."""
        with transaction.atomic():
            expired = Session.objects.filter(expire_date__lt=timezone.now())
            UserSession.objects.filter(session_key__in=expired.values("session_key")).delete()
            expired.delete()

    async def asave(self, must_create: bool = False) -> None:
        await sync_to_async(self.save, thread_sensitive=True)(must_create=must_create)

    async def adelete(self, session_key: str | None = None) -> None:
        await sync_to_async(self.delete, thread_sensitive=True)(session_key)
