"""Integration tests use disposable media even when they select development settings."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from services.platform.tests.media import isolated_media


@pytest.fixture(scope="session", autouse=True)
def isolated_test_media() -> Iterator[None]:
    with isolated_media():
        yield
