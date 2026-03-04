"""Shared utilities for Portal API response handling."""

from typing import Any

from django.utils import timezone
from django.utils.dateparse import parse_datetime


class DictAsObj:
    """Simple wrapper to allow dot notation access on dictionaries for Django templates.

    Converts nested dicts recursively and parses ISO 8601 date strings
    (created_at, updated_at) into timezone-aware datetime objects so that
    Django's |date template filter works correctly.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        for key, value in data.items():
            if isinstance(value, dict):
                setattr(self, key, DictAsObj(value))
            elif key in ("created_at", "updated_at") and isinstance(value, str):
                parsed_date = parse_datetime(value)
                if parsed_date:
                    if timezone.is_naive(parsed_date):
                        parsed_date = timezone.make_aware(parsed_date)
                    setattr(self, key, parsed_date)
                else:
                    setattr(self, key, value)
            else:
                setattr(self, key, value)
