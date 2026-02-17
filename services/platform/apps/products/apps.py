"""
Django app configuration for Products app
"""

from django.apps import AppConfig


class ProductsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.products"
    verbose_name = "Product Catalog"

    def ready(self) -> None:
        """Register signals when app is ready"""
        import apps.products.signals  # noqa: F401
