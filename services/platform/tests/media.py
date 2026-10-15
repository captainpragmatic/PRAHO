"""Disposable filesystem media for Django and pytest suites, including spawned workers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from tempfile import TemporaryDirectory

from django.conf import settings
from django.test import override_settings


def _media_settings(directory: str) -> override_settings:
    return override_settings(
        MEDIA_ROOT=directory,
        STORAGES={
            **settings.STORAGES,
            "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        },
    )


@contextmanager
def isolated_media() -> Iterator[str]:
    """Use real filesystem writes, then remove only this run's temporary directory."""
    with TemporaryDirectory(prefix="praho-tests-media-") as directory, _media_settings(directory):
        yield directory


def setup_worker_media(directory: str) -> None:
    """Spawn does not inherit settings overrides; the parent owns directory cleanup."""
    _media_settings(directory).enable()
