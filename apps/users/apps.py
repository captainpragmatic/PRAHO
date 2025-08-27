"""
Django app configuration for Users app
"""

from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.users'
    verbose_name = 'Users'

    def ready(self) -> None:
        from . import signals  # noqa: F401,PLC0415 # Django app signal registration pattern
