"""Bounded monitoring settings; all reads occur at call time."""

from apps.settings.services import SettingsService

JOB_TIMEOUT = 120
LEASE_SECONDS = 180
RETRY_SECONDS = 300


def enabled() -> bool:
    return SettingsService.get_boolean_setting("dns.hosted_checks_enabled", True)


def batch_size() -> int:
    return max(1, min(200, SettingsService.get_integer_setting("dns.hosted_checks_batch_size", 50)))


def interval_seconds() -> int:
    return max(300, min(86400, SettingsService.get_integer_setting("dns.hosted_checks_interval_seconds", 3600)))


def recheck_cooldown_seconds() -> int:
    return max(30, min(3600, SettingsService.get_integer_setting("dns.hosted_recheck_cooldown_seconds", 60)))
