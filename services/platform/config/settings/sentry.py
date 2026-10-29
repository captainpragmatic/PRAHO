"""What a production error report may carry: no frame locals, and secrets scrubbed at any depth.

Frame locals hold registrant data and transfer codes under ordinary names (data, config), which no
denylist can name, so they are not sent at all. Imported only when sentry_sdk is installed.
"""

from collections.abc import Callable
from typing import Any, TypedDict

from sentry_sdk.scrubber import DEFAULT_DENYLIST, EventScrubber
from sentry_sdk.utils import AnnotatedValue

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
    """Sentry's scrubber, walking tuples as well as dicts and lists, without recursion.

    It runs before Sentry serialises the event, which turns anything nested past its depth limit
    into text that no later callback can scrub, so a dict inside a tuple must be scrubbed here.
    The walk keeps its own stack and the containers it has seen: a cycle, through a tuple or not,
    and any depth, never stop it before the fields after them are scrubbed.
    """

    def scrub_dict(self, d: object) -> None:
        self._walk(d)

    def scrub_list(self, lst: object) -> None:
        self._walk(lst)

    def _walk(self, root: object) -> None:
        stack, seen = [root], set()
        while stack:
            value = stack.pop()
            if not isinstance(value, (dict, list, tuple)) or id(value) in seen:
                continue
            seen.add(id(value))
            if not isinstance(value, dict):
                stack.extend(value)
                continue
            for key, item in value.items():
                if isinstance(key, str) and key.lower() in self.denylist:
                    value[key] = AnnotatedValue.substituted_because_contains_sensitive_data()
                elif self.recursive:
                    stack.append(item)


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
