"""The HTML a published legal document may contain. Identical in both services.

Platform renders a document's Markdown and sanitises the result when staff publish it; the portal
sanitises again the HTML it receives, so customers only ever see what this allowlist lets through.
Headings, lists, links, emphasis, quotes and tables are what legal text needs. No attribute but a
link's address and title survives, and a link must be http, https or mailto.
"""

from __future__ import annotations

import bleach
from django.utils.safestring import SafeString, mark_safe

_TAGS = frozenset(
    {
        *("h1", "h2", "h3", "h4", "p", "br", "hr", "blockquote", "strong", "em", "a"),
        *("ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td"),
    }
)
_ATTRIBUTES = {"a": ["href", "title"]}
_PROTOCOLS = frozenset({"http", "https", "mailto"})


def sanitize_legal_html(html: str) -> SafeString:
    """Keep only the allowlisted markup, safe to render. A disallowed tag is removed and its text kept, escaped."""
    cleaned = bleach.clean(html, tags=_TAGS, attributes=_ATTRIBUTES, protocols=_PROTOCOLS, strip=True)
    # nosemgrep: avoid-mark-safe — the markup was just reduced to the allowlist above
    return mark_safe(cleaned)  # nosec B308 B703  # noqa: S308
