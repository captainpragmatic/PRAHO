"""
System Settings Django App Configuration
"""

from __future__ import annotations

import contextlib
from typing import Any

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class SystemSettingsConfig(AppConfig):
    """⚙️ System Settings application configuration"""
    
    default_auto_field: str = 'django.db.models.BigAutoField'
    name: str = 'apps.settings'
    verbose_name: Any = _('⚙️ System Settings')  # _StrPromise from gettext_lazy
    
    def ready(self) -> None:
        """Initialize app when Django starts"""
        # Import signals to register them
        with contextlib.suppress(ImportError):
            from . import signals  # noqa: F401,PLC0415  # Signals must be imported after Django ready
