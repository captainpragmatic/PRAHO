"""What a production error report may carry: no frame locals, and secrets scrubbed at any depth.

Frame locals hold registrant data and transfer codes under ordinary names (data, config), which no
denylist can name, so they are not sent at all. Imported only when sentry_sdk is installed.
"""

from collections.abc import Callable, Mapping
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


class _TupleScrubber(EventScrubber):
    """Sentry's scrubber, walking tuples as well as dicts and lists, without recursion.

    It runs before Sentry serialises the event, which turns anything nested past its depth limit
    into text that no later callback can scrub, so a dict inside a tuple must be scrubbed here.
    The walk keeps its own stack and the containers it has seen: a cycle, through a tuple or not,
    and any depth, never stop it before the fields after them are scrubbed.
    """

    def scrub_event(self, event: Any) -> None:
        # Sentry's own pass skips contexts, tags, the log message's parameters and exception data;
        # the walk covers the whole event, before serialisation writes any "_meta" annotation.
        super().scrub_event(event)
        self._walk(event)

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


def _render_redacted_log_entry(event: Any) -> None:
    """Sentry renders a logged message from its raw parameters; render it again from redacted ones.

    "submitted=%(password)s" renders the password under a key no text scan can recognise, so the parameters are
    redacted by key first. "password=%s" has no key on its argument, so an argument the message places as a
    sensitive value is withheld by where it sits. Sentry sends positional arguments as a list; they format as the
    tuple logging had. A message that doesn't format with them keeps no rendered text at all.
    """
    from apps.common.logging import (  # noqa: PLC0415  # Settings import before apps are ready
        REDACTION_TEXT,
        redact_placed_arguments,
        redact_sensitive_data,
        redact_sensitive_text,
        render_log_message,
    )

    entry = event.get("logentry") if isinstance(event, dict) else None
    if not isinstance(entry, dict) or not entry.get("params"):
        return
    message = str(entry.get("message", ""))
    params = redact_placed_arguments(message, redact_sensitive_data(entry["params"]))
    try:
        rendered = render_log_message(message, params)
    except (TypeError, ValueError, KeyError, IndexError):
        rendered = message
    entry["formatted"] = redact_sensitive_text(rendered)
    if entry["formatted"] != rendered:
        # The text held a value no key or placement accounted for ("%s=%s" with the key as an argument, a "*"
        # width): which parameter carried it is unknown, so none is sent.
        if isinstance(params, Mapping):
            params = dict.fromkeys(params, REDACTION_TEXT)
        else:
            params = [REDACTION_TEXT] * len(params) if isinstance(params, list | tuple) else REDACTION_TEXT
    entry["params"] = params


def scrub_event(event: Any, hint: Any) -> Any:
    """Secret links and the values of sensitive keys, wherever they sit in the event (exception text included).

    Sentry builds its exception from the record's exc_info, never from the log filter's redacted text, and its
    logging integration reads records before any handler's filters run.
    """
    from apps.common.logging import redact_sensitive_data  # noqa: PLC0415  # Settings import before apps are ready

    _render_redacted_log_entry(event)
    return redact_sensitive_data(scrub_sentry_event(event, hint))


def sentry_options(dsn: str, *, release: str) -> SentryOptions:
    """The sentry_sdk.init arguments every production deployment uses, integrations aside."""
    return {
        "dsn": dsn,
        "before_send": scrub_event,
        "before_send_transaction": scrub_event,
        "traces_sample_rate": 0.1,
        "send_default_pii": False,
        "include_local_variables": False,
        "event_scrubber": _TupleScrubber(denylist=[*DEFAULT_DENYLIST, *SECRET_KEYS], recursive=True),
        "environment": "production",
        "release": release,
    }
