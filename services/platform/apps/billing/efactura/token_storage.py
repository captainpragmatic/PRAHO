"""
Database-backed OAuth2 token storage for e-Factura.

Stores tokens securely with encryption for production use.
Provides automatic refresh and expiration handling.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.db import models
from django.utils import timezone

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class OAuthTokenManager(models.Manager["OAuthToken"]):
    """Manager for OAuth tokens."""

    def get_valid_token(self, cui: str) -> "OAuthToken | None":
        """Get a valid (non-expired) token for a CUI."""
        now = timezone.now()
        return (
            self.filter(
                cui=cui,
                is_active=True,
                expires_at__gt=now,
            )
            .order_by("-created_at")
            .first()
        )

    def get_refreshable_token(self, cui: str) -> "OAuthToken | None":
        """Get a token that can be refreshed (has refresh token)."""
        return (
            self.filter(
                cui=cui,
                is_active=True,
                refresh_token__isnull=False,
            )
            .exclude(refresh_token="")
            .order_by("-created_at")
            .first()
        )

    def deactivate_all(self, cui: str) -> int:
        """Deactivate all tokens for a CUI."""
        return self.filter(cui=cui, is_active=True).update(
            is_active=False,
            updated_at=timezone.now(),
        )


class OAuthToken(models.Model):
    """
    Secure storage for ANAF OAuth2 tokens.

    Tokens are encrypted at rest using the settings app encryption service.
    """

    cui = models.CharField(
        max_length=20,
        db_index=True,
        help_text="Company CUI this token belongs to",
    )

    # Encrypted token fields
    access_token = models.TextField(
        help_text="Encrypted access token",
    )

    refresh_token = models.TextField(
        blank=True,
        default="",
        help_text="Encrypted refresh token",
    )

    token_type = models.CharField(
        max_length=50,
        default="Bearer",
        help_text="Token type (usually Bearer)",
    )

    scope = models.TextField(
        blank=True,
        default="",
        help_text="OAuth scopes granted",
    )

    # Expiration
    expires_at = models.DateTimeField(
        help_text="When the access token expires",
    )

    refresh_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the refresh token expires (if known)",
    )

    # Environment
    environment = models.CharField(
        max_length=20,
        default="test",
        choices=[("test", "Test"), ("production", "Production")],
        help_text="ANAF environment this token is for",
    )

    # Status
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Whether this token is currently active",
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Last used tracking
    last_used_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this token was last used",
    )

    use_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of times this token was used",
    )

    objects = OAuthTokenManager()

    class Meta:
        db_table = "billing_efactura_oauth_token"
        verbose_name = "e-Factura OAuth Token"
        verbose_name_plural = "e-Factura OAuth Tokens"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["cui", "is_active"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self) -> str:
        status = "active" if self.is_active and not self.is_expired else "expired"
        return f"OAuth Token for {self.cui} ({status})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Save with automatic encryption."""
        # Encrypt tokens before saving
        if self.access_token and not self._is_encrypted(self.access_token):
            self.access_token = self._encrypt(self.access_token)

        if self.refresh_token and not self._is_encrypted(self.refresh_token):
            self.refresh_token = self._encrypt(self.refresh_token)

        super().save(*args, **kwargs)

    def _encrypt(self, value: str) -> str:
        """Encrypt a value using settings encryption."""
        try:
            from apps.settings.encryption import SettingsEncryption

            encryption = SettingsEncryption()
            return encryption.encrypt_value(value)
        except ImportError:
            logger.warning("Encryption service not available, storing token unencrypted")
            return value
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return value

    def _decrypt(self, value: str) -> str:
        """Decrypt a value using settings encryption."""
        try:
            from apps.settings.encryption import SettingsEncryption

            encryption = SettingsEncryption()
            if encryption.is_encrypted(value):
                return encryption.decrypt_value(value)
            return value
        except ImportError:
            return value
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return value

    def _is_encrypted(self, value: str) -> bool:
        """Check if a value is encrypted."""
        try:
            from apps.settings.encryption import SettingsEncryption

            encryption = SettingsEncryption()
            return encryption.is_encrypted(value)
        except ImportError:
            return False

    @property
    def decrypted_access_token(self) -> str:
        """Get decrypted access token."""
        return self._decrypt(self.access_token)

    @property
    def decrypted_refresh_token(self) -> str:
        """Get decrypted refresh token."""
        return self._decrypt(self.refresh_token) if self.refresh_token else ""

    @property
    def is_expired(self) -> bool:
        """Check if access token is expired."""
        return timezone.now() >= self.expires_at

    @property
    def is_refresh_expired(self) -> bool:
        """Check if refresh token is expired."""
        if not self.refresh_expires_at:
            return False
        return timezone.now() >= self.refresh_expires_at

    @property
    def expires_in_seconds(self) -> int:
        """Get seconds until expiration."""
        delta = self.expires_at - timezone.now()
        return max(0, int(delta.total_seconds()))

    @property
    def can_refresh(self) -> bool:
        """Check if token can be refreshed."""
        return bool(self.refresh_token) and not self.is_refresh_expired

    def mark_used(self) -> None:
        """Update last used timestamp and count."""
        self.last_used_at = timezone.now()
        self.use_count += 1
        self.save(update_fields=["last_used_at", "use_count", "updated_at"])

    def deactivate(self) -> None:
        """Deactivate this token."""
        self.is_active = False
        self.save(update_fields=["is_active", "updated_at"])

    @classmethod
    def store_token(
        cls,
        cui: str,
        access_token: str,
        expires_in: int,
        refresh_token: str = "",
        token_type: str = "Bearer",
        scope: str = "",
        environment: str = "test",
        refresh_expires_in: int | None = None,
    ) -> "OAuthToken":
        """
        Store a new OAuth token.

        Deactivates any existing tokens for the CUI.

        Args:
            cui: Company CUI
            access_token: Access token string
            expires_in: Seconds until expiration
            refresh_token: Refresh token string
            token_type: Token type (default: Bearer)
            scope: OAuth scopes
            environment: ANAF environment
            refresh_expires_in: Seconds until refresh token expires

        Returns:
            Created OAuthToken instance
        """
        # Deactivate existing tokens
        cls.objects.deactivate_all(cui)

        # Calculate expiration
        now = timezone.now()
        expires_at = now + timedelta(seconds=expires_in)
        refresh_expires_at = None
        if refresh_expires_in:
            refresh_expires_at = now + timedelta(seconds=refresh_expires_in)

        # Create new token
        token = cls.objects.create(
            cui=cui,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=token_type,
            scope=scope,
            expires_at=expires_at,
            refresh_expires_at=refresh_expires_at,
            environment=environment,
        )

        logger.info(
            f"Stored new OAuth token for {cui} "
            f"(expires: {expires_at.isoformat()}, env: {environment})"
        )

        return token

    @classmethod
    def get_valid_access_token(cls, cui: str) -> str | None:
        """
        Get a valid access token for a CUI.

        Args:
            cui: Company CUI

        Returns:
            Decrypted access token or None if not found/expired
        """
        token = cls.objects.get_valid_token(cui)
        if token:
            token.mark_used()
            return token.decrypted_access_token
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (for API responses)."""
        return {
            "cui": self.cui,
            "token_type": self.token_type,
            "expires_at": self.expires_at.isoformat(),
            "expires_in_seconds": self.expires_in_seconds,
            "is_expired": self.is_expired,
            "can_refresh": self.can_refresh,
            "environment": self.environment,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "use_count": self.use_count,
        }


class TokenStorageService:
    """
    Service for managing OAuth tokens with caching.

    Provides a high-level interface for token storage and retrieval.
    """

    CACHE_PREFIX = "efactura_token"
    CACHE_TIMEOUT = 300  # 5 minutes

    def __init__(self, settings: Any = None):
        """Initialize with optional settings override."""
        from .settings import efactura_settings

        self._settings = settings or efactura_settings

    def _get_cache_key(self, cui: str) -> str:
        """Generate cache key for token."""
        return f"{self.CACHE_PREFIX}:{cui}"

    def get_access_token(self, cui: str | None = None) -> str | None:
        """
        Get valid access token for a CUI.

        Uses cache for performance, falls back to database.

        Args:
            cui: Company CUI. If None, uses company CUI from settings.

        Returns:
            Access token or None
        """
        from django.core.cache import cache

        cui = cui or self._settings.company_cui
        if not cui:
            logger.warning("No CUI provided and no company CUI in settings")
            return None

        # Check cache first
        cache_key = self._get_cache_key(cui)
        cached_token = cache.get(cache_key)
        if cached_token:
            return cached_token

        # Get from database
        token = OAuthToken.get_valid_access_token(cui)
        if token:
            # Cache for shorter period than expiration
            cache.set(cache_key, token, timeout=self.CACHE_TIMEOUT)
            return token

        return None

    def store_token(
        self,
        access_token: str,
        expires_in: int,
        refresh_token: str = "",
        token_type: str = "Bearer",
        scope: str = "",
        cui: str | None = None,
    ) -> OAuthToken:
        """
        Store a new token.

        Args:
            access_token: Access token
            expires_in: Seconds until expiration
            refresh_token: Refresh token
            token_type: Token type
            scope: OAuth scopes
            cui: Company CUI. If None, uses company CUI from settings.

        Returns:
            Created OAuthToken
        """
        from django.core.cache import cache

        cui = cui or self._settings.company_cui
        if not cui:
            raise ValueError("No CUI provided and no company CUI in settings")

        # Store in database
        token = OAuthToken.store_token(
            cui=cui,
            access_token=access_token,
            expires_in=expires_in,
            refresh_token=refresh_token,
            token_type=token_type,
            scope=scope,
            environment=self._settings.environment.value,
        )

        # Update cache
        cache_key = self._get_cache_key(cui)
        cache.set(cache_key, token.decrypted_access_token, timeout=self.CACHE_TIMEOUT)

        return token

    def invalidate_token(self, cui: str | None = None) -> None:
        """
        Invalidate token for a CUI.

        Args:
            cui: Company CUI. If None, uses company CUI from settings.
        """
        from django.core.cache import cache

        cui = cui or self._settings.company_cui
        if not cui:
            return

        # Deactivate in database
        OAuthToken.objects.deactivate_all(cui)

        # Clear cache
        cache_key = self._get_cache_key(cui)
        cache.delete(cache_key)

        logger.info(f"Invalidated tokens for {cui}")

    def get_refreshable_token(self, cui: str | None = None) -> OAuthToken | None:
        """
        Get a token that can be refreshed.

        Args:
            cui: Company CUI. If None, uses company CUI from settings.

        Returns:
            OAuthToken with refresh token or None
        """
        cui = cui or self._settings.company_cui
        if not cui:
            return None

        return OAuthToken.objects.get_refreshable_token(cui)


# Module-level service instance
token_storage = TokenStorageService()
