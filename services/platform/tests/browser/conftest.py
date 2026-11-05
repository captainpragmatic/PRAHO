"""The full checkout gate owns exactly one disposable PostgreSQL database."""

import os

import pytest
from django.conf import settings


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("HOSTING_CHECKOUT_FULL") == "1":
        return
    excluded = [item for item in items if item.get_closest_marker("checkout_browser")]
    if excluded:
        config.hook.pytest_deselected(items=excluded)
        items[:] = [item for item in items if item not in excluded]


@pytest.fixture(scope="session")
def django_db_modify_db_settings() -> None:
    assert os.environ.get("HOSTING_CHECKOUT_FULL") == "1"
    database = settings.DATABASES["default"]
    assert database["ENGINE"] == "django.db.backends.postgresql"
    assert database["HOST"] in {"127.0.0.1", "localhost"}
    assert database["NAME"] == "hosting_browser", "Refusing a non-owned browser database"
    database["TEST"]["NAME"] = "test_hosting_browser"
