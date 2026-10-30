"""The browser a session is bound to: its family and operating system, without versions.

A browser update keeps the identity; another browser or another operating system changes it
(ADR-0017 section 5). User agents name several families at once (Edge and Opera also say Chrome,
Chrome also says Safari), so the more specific ones are checked first.
"""

from __future__ import annotations

import re

_FAMILIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("edge", re.compile(r"\b(Edg|EdgA|EdgiOS|Edge)/")),
    ("opera", re.compile(r"\b(OPR|Opera)/")),
    ("firefox", re.compile(r"\b(Firefox|FxiOS)/")),
    ("chrome", re.compile(r"\b(Chrome|CriOS|Chromium)/")),
    ("safari", re.compile(r"\bSafari/")),
)
_SYSTEMS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ios", re.compile(r"\b(iPhone|iPad|iPod)\b")),
    ("android", re.compile(r"\bAndroid\b")),
    ("windows", re.compile(r"\bWindows\b")),
    ("macos", re.compile(r"\b(Macintosh|Mac OS X)\b")),
    ("linux", re.compile(r"\b(Linux|X11)\b")),
)


def _first(user_agent: str, candidates: tuple[tuple[str, re.Pattern[str]], ...]) -> str:
    return next((name for name, pattern in candidates if pattern.search(user_agent)), "other")


def browser_identity(user_agent: str) -> str:
    """``family/system``, for example ``chrome/macos``; ``other`` for what it does not recognise."""
    return f"{_first(user_agent, _FAMILIES)}/{_first(user_agent, _SYSTEMS)}"
