"""
Portal Customers App Configuration
Handles customer team management, tax profiles, and addresses via Platform API.
"""

from django.apps import AppConfig


class CustomersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.customers"
    verbose_name = "Portal Customers"
