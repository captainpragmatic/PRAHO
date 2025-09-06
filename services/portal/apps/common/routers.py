"""
Database router for Portal service - prevents all database operations.
Portal is stateless and should never touch a database.
"""

from typing import Optional, Any


class NoMigrationsRouter:
    """
    Database router that prevents all migrations and database operations.
    Portal service should never create tables or store data.
    """

    def allow_migrate(self, db: str, app_label: str, model_name: Optional[str] = None, **hints: Any) -> bool:
        """
        Portal has no models and should never run migrations.
        Return False to prevent all migrations.
        """
        return False

    def allow_relation(self, obj1: Any, obj2: Any, **hints: Any) -> Optional[bool]:
        """
        Portal should not have any model relations.
        """
        return False

    def db_for_read(self, model: Any, **hints: Any) -> Optional[str]:
        """
        Portal should never read from database.
        """
        return None

    def db_for_write(self, model: Any, **hints: Any) -> Optional[str]:
        """
        Portal should never write to database.
        """
        return None
