"""What a production error report may carry: no frame locals, and secrets scrubbed at any depth.

Frame locals hold registrant data and transfer codes under ordinary names (data, config), which no
denylist can name, so they are not sent at all. Imported only when sentry_sdk is installed.
"""

from collections.abc import Callable
from typing import Any, TypedDict

from sentry_sdk.scrubber import DEFAULT_DENYLIST, EventScrubber

from apps.common.secret_urls import scrub_sentry_event

SECRET_KEYS = ("cnp", "cnp_fiscal_code", "epp_code", "auth_code", "authorization_key", "transfer_code")


class SentryOptions(TypedDict):
    dsn: str
    traces_sample_rate: float
    send_default_pii: bool
    include_local_variables: bool
    event_scrubber: EventScrubber
    environment: str
    release: str
    before_send: Callable[[Any, Any], Any]
    before_send_transaction: Callable[[Any, Any], Any]


def sentry_options(dsn: str, *, release: str) -> SentryOptions:
    """The sentry_sdk.init arguments every production deployment uses, integrations aside."""
    return {
        "dsn": dsn,
        "before_send": scrub_sentry_event,
        "before_send_transaction": scrub_sentry_event,
        "traces_sample_rate": 0.1,
        "send_default_pii": False,
        "include_local_variables": False,
        "event_scrubber": EventScrubber(denylist=[*DEFAULT_DENYLIST, *SECRET_KEYS], recursive=True),
        "environment": "production",
        "release": release,
    }
