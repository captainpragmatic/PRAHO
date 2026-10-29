"""What a production error report may carry: no frame locals, and secrets scrubbed at any depth.

Frame locals hold registrant data and transfer codes under ordinary names (data, config), which no
denylist can name, so they are not sent at all. Imported only when sentry_sdk is installed.
"""

from collections.abc import Callable
from typing import Any, TypedDict

from sentry_sdk.scrubber import DEFAULT_DENYLIST, EventScrubber

from apps.common.secret_urls import scrub_sentry_event

# Sentry's own denylist covers passwords and tokens; these are PRAHO's other secrets: registrant
# identity and domain transfer codes, the identity check's code and the portal session's id.
SECRET_KEYS = (
    "cnp",
    "cnp_fiscal_code",
    "epp_code",
    "auth_code",
    "authorization_key",
    "transfer_code",
    "mfa_code",
    "session_id",
    "portal_session_id",
)
_DENIED = frozenset(name.lower() for name in (*DEFAULT_DENYLIST, *SECRET_KEYS))
_FILTERED = "[Filtered]"
_MAX_DEPTH = 32


def _drop_secret_fields(value: Any, path: frozenset[int] = frozenset(), depth: int = 0) -> Any:
    """A copy with every denylisted field filtered at any depth, tuples included.

    Sentry's own scrubber walks dicts and lists but not tuples. A container met again on its own
    path, or nested past the bound, is replaced rather than recursed into.
    """
    if not isinstance(value, (dict, list, tuple)):
        return value
    if id(value) in path or depth >= _MAX_DEPTH:
        return _FILTERED
    inner = path | {id(value)}
    if isinstance(value, dict):
        return {
            key: _FILTERED
            if isinstance(key, str) and key.lower() in _DENIED
            else _drop_secret_fields(item, inner, depth + 1)
            for key, item in value.items()
        }
    items = [_drop_secret_fields(item, inner, depth + 1) for item in value]
    return tuple(items) if isinstance(value, tuple) else items


class _TupleScrubber(EventScrubber):
    """Sentry's scrubber, walking tuples as well as lists.

    It runs before Sentry serialises the event, which turns anything nested past its depth limit
    into text that no later callback can scrub; a dict inside a tuple must be scrubbed here.
    """

    def scrub_list(self, lst: object) -> None:
        if not isinstance(lst, tuple):
            super().scrub_list(lst)
            return
        for value in lst:
            self.scrub_dict(value)
            self.scrub_list(value)


def _before_send(event: Any, hint: Any) -> Any:
    return _drop_secret_fields(scrub_sentry_event(event, hint))


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
        "before_send": _before_send,
        "before_send_transaction": _before_send,
        "traces_sample_rate": 0.1,
        "send_default_pii": False,
        "include_local_variables": False,
        "event_scrubber": _TupleScrubber(denylist=[*DEFAULT_DENYLIST, *SECRET_KEYS], recursive=True),
        "environment": "production",
        "release": release,
    }
