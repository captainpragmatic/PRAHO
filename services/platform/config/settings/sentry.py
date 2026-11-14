"""What a production error report may carry: no frame locals, and secrets scrubbed at any depth.

Frame locals hold registrant data and transfer codes under ordinary names (data, config), which no
denylist can name, so they are not sent at all. Imported only when sentry_sdk is installed.
"""

from collections.abc import Callable, Mapping
from typing import Any, TypedDict

from sentry_sdk.consts import DEFAULT_MAX_VALUE_LENGTH
from sentry_sdk.scrubber import DEFAULT_DENYLIST, EventScrubber
from sentry_sdk.utils import AnnotatedValue, strip_string

from apps.common.secret_urls import scrub_sentry_event

# What Sentry's own scrub writes in place of a denylisted value, beside a "_meta" annotation saying so.
_SENTRY_SUBSTITUTE = AnnotatedValue.substituted_because_contains_sensitive_data().value

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
        rendered, unplaced = message, True  # Arguments the message can't format have no placement to judge
    else:
        unplaced = False
    entry["formatted"] = redact_sensitive_text(rendered)
    if unplaced or entry["formatted"] != rendered:
        # The text held a value no key or placement accounted for ("%s=%s" with the key as an argument, a "*"
        # width): which parameter carried it is unknown, so none is sent.
        if isinstance(params, Mapping):
            params = dict.fromkeys(params, REDACTION_TEXT)
        else:
            params = [REDACTION_TEXT] * len(params) if isinstance(params, list | tuple) else REDACTION_TEXT
    entry["params"] = params


def _substituted_paths(event: dict[str, Any], meta: Any, path: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """Where Sentry's own scrub put its substitute and annotated it: request data, headers, extras, any section.

    Only a substitution ("s" in the annotation's removal) whose value is still Sentry's substitute; a length or
    trimming annotation marks content that stays and is redacted like any other.
    """
    if not isinstance(meta, dict):
        return []
    found: list[tuple[str, ...]] = []
    for key, child in meta.items():
        if key == "":
            removals = child.get("rem", []) if isinstance(child, dict) else []
            substituted = any(isinstance(rule, list) and rule[1:2] == ["s"] for rule in removals)
            if substituted and _at(event, path) == _SENTRY_SUBSTITUTE:
                found.append(path)
        else:
            found.extend(_substituted_paths(event, child, (*path, key)))
    return found


_MISSING = object()


def _at(value: Any, path: tuple[str, ...]) -> Any:
    """The value at an annotation's path ("_meta" names a list index as a string), or _MISSING."""
    for key in path:
        if isinstance(value, dict) and key in value:
            value = value[key]
        elif isinstance(value, list) and key.isdigit() and int(key) < len(value):
            value = value[int(key)]
        else:
            return _MISSING
    return value


def _resolving_meta(meta: Any, value: Any) -> Any:
    """The annotations whose paths still lead somewhere in the redacted event; the rest are dropped.

    A field redacted whole, or renamed because its name held a secret, leaves no path for its annotations to
    describe, and an annotation path that outlived it would carry the old name.
    """
    if not isinstance(meta, dict):
        return meta
    kept: dict[str, Any] = {}
    for key, child in meta.items():
        if key == "":
            kept[key] = child
            continue
        target = _at(value, (key,))
        if target is not _MISSING:
            pruned = _resolving_meta(child, target)
            if pruned:
                kept[key] = pruned
    return kept


def _rebuild_structured_message(event: Any, hint: Any) -> None:
    """A mapping, list or tuple logged as the message itself, written again from the structure redacted by key.

    Sentry wrote it as text, where a key like "password value" can't be recognised. It runs before every other
    scrub, so the secret-URL scrub and the text redaction still read the rebuilt text, and it is trimmed to
    Sentry's own length limit, since Sentry's trimming of the original text has already run.
    """
    from apps.common.logging import redact_sensitive_data  # noqa: PLC0415  # Settings import before apps are ready

    entry = event.get("logentry") if isinstance(event, dict) else None
    record = hint.get("log_record") if isinstance(hint, dict) else None
    if not isinstance(entry, dict) or not isinstance(getattr(record, "msg", None), Mapping | list | tuple):
        return
    text = strip_string(str(redact_sensitive_data(record.msg)), max_length=DEFAULT_MAX_VALUE_LENGTH)
    entry["message"] = entry["formatted"] = text.value if isinstance(text, AnnotatedValue) else text


def scrub_event(event: Any, hint: Any) -> Any:
    """Secret links and the values of sensitive keys, wherever they sit in the event (exception text included).

    Sentry's own scrub has already blanked the fields its denylist names and recorded each removal in "_meta":
    the annotations are left as they are, and so is each value Sentry substituted, so the report still says what
    was removed. Everything else is redacted here, by key and as text. Sentry builds its exception from the
    record's exc_info, never from the log filter's redacted text, and its logging integration reads records before
    any handler's filters run.
    """
    from apps.common.logging import redact_sensitive_data  # noqa: PLC0415  # Settings import before apps are ready

    _rebuild_structured_message(event, hint)
    event = scrub_sentry_event(event, hint)
    if not isinstance(event, dict):
        return redact_sensitive_data(event)
    meta = event.pop("_meta", None)
    substituted = _substituted_paths(event, meta)
    _render_redacted_log_entry(event)
    redacted = redact_sensitive_data(event)
    for path in substituted:
        container = _at(redacted, path[:-1])
        if isinstance(container, dict) and path[-1] in container:
            container[path[-1]] = _SENTRY_SUBSTITUTE
        elif isinstance(container, list) and path[-1].isdigit() and int(path[-1]) < len(container):
            container[int(path[-1])] = _SENTRY_SUBSTITUTE
    if meta is not None:
        redacted["_meta"] = _resolving_meta(meta, redacted)
    return redacted


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
