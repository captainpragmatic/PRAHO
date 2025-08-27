"""
Django app configuration for Users app
"""

from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.users'
    verbose_name = 'Users'

    def ready(self) -> None:
        pass  # Django app signals pattern requires import in ready()
