"""Platform pytest runs use disposable filesystem media, including with dev settings."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from tests.field_lengths import install_sqlite_length_check
from tests.media import isolated_media


@pytest.fixture(scope="session", autouse=True)
def isolated_test_media() -> Iterator[None]:
    """pytest does not use Django's test runner."""
    with isolated_media():
        yield


@pytest.fixture(scope="session", autouse=True)
def sqlite_length_check() -> None:
    """The Django runners install this; pytest does not run them."""
    install_sqlite_length_check()
