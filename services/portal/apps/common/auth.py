"""
Stateless authentication backend for PRAHO Portal Service
Authenticates users via Platform API without local User models.
"""

import logging
from typing import Any

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest

from apps.api_client.services import PlatformAPIError, api_client

logger = logging.getLogger(__name__)


class APIUser:
    """
    Lightweight user class that mimics Django's User for template compatibility.
    All data comes from Platform API responses.
    """
    
    def __init__(self, user_data: dict[str, Any]):
        """Initialize from Platform API user data."""
        self.id = user_data.get('id')
        self.email = user_data.get('email', '')
        self.first_name = user_data.get('first_name', '')
        self.last_name = user_data.get('last_name', '')
        self.is_active = user_data.get('is_active', True)
        self.is_staff = user_data.get('is_staff', False)
        self.date_joined = user_data.get('date_joined')
        self.last_login = user_data.get('last_login')
        
        # Store full API data for additional fields
        self._api_data = user_data
    
    @property
    def is_authenticated(self) -> bool:
        """Always True for APIUser instances."""
        return True
    
    @property 
    def is_anonymous(self) -> bool:
        """Always False for APIUser instances."""
        return False
    
    def get_full_name(self) -> str:
        """Return full name."""
        return f"{self.first_name} {self.last_name}".strip() or self.email
    
    def get_short_name(self) -> str:
        """Return first name or email."""
        return self.first_name or self.email
    
    def get_username(self) -> str:
        """Return email as username."""
        return self.email
    
    def __str__(self) -> str:
        return self.email


class PlatformAPIAuthenticationBackend(BaseBackend):
    """
    Authentication backend that validates credentials with Platform API.
    Returns APIUser instance on successful authentication.
    """
    
    def authenticate(
        self,
        request: HttpRequest | None,
        username: str | None = None,
        password: str | None = None,
        **kwargs: Any
    ) -> APIUser | None:
        """
        Authenticate user via Platform API.
        
        Args:
            request: HTTP request (unused but required by interface)
            username: User's email
            password: User's password
            
        Returns:
            APIUser instance on success, None on failure
        """
        if not username or not password:
            return None
            
        try:
            # Call Platform API to authenticate
            user_data = api_client.authenticate_user(username, password)
            
            if user_data:
                logger.info(f"✅ [Auth] Successfully authenticated user {username}")
                return APIUser(user_data)
            else:
                logger.warning(f"⚠️ [Auth] Authentication failed for user {username}")
                return None
                
        except PlatformAPIError as e:
            logger.error(f"🔥 [Auth] Platform API error during authentication: {e}")
            return None
    
    def get_user(self, user_id: Any) -> APIUser | None:
        """
        Get user by ID from Platform API.
        Called by Django to refresh user data from session.
        """
        try:
            user_data = api_client.get_user_by_id(user_id)
            
            if user_data:
                return APIUser(user_data)
            else:
                return None
                
        except PlatformAPIError as e:
            logger.error(f"🔥 [Auth] Failed to get user {user_id}: {e}")
            return None


def get_current_user(request: HttpRequest) -> APIUser:
    """
    Get current authenticated user or raise exception.
    Helper function for views that require authentication.
    """
    if not hasattr(request, 'user') or isinstance(request.user, AnonymousUser):
        raise ValueError("User not authenticated")
    
    if not isinstance(request.user, APIUser):
        raise ValueError("Invalid user type - expected APIUser")
    
    return request.user
