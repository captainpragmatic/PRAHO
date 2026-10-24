"""Every edge access log redacts bearer links in the Location header too (#751 follow-up, M6a).

Each log block already redacted bearer links in the request URI and the Referer header. A redirect to a
link that carries a token (Django's trailing-slash 301 on a password-reset or unsubscribe link) puts the
token in the response's Location header, which every access log recorded as is.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = (
    "deploy/caddy/Caddyfile",
    "deploy/caddy/Caddyfile.portal",
    "deploy/caddy/Caddyfile.platform",
    "deploy/ansible/roles/praho-native/templates/Caddyfile.native.j2",
)
# One `fields { ... }` block per access log filter.
FIELDS = re.compile(r"format filter \{\s*wrap json\s*fields \{(?P<body>.*?)\n\s*\}", re.S)
RULE = re.compile(r'^\s*(?P<field>\S+) regexp (?P<pattern>".*") "\$\{1\}\[REDACTED\]"$', re.M)


def _blocks() -> list[tuple[str, dict[str, str]]]:
    blocks = []
    for name in CONFIGS:
        for match in FIELDS.finditer((ROOT / name).read_text()):
            rules = {rule["field"]: rule["pattern"] for rule in RULE.finditer(match["body"])}
            blocks.append((name, rules))
    return blocks


def test_every_access_log_redacts_the_location_header_like_the_uri() -> None:
    blocks = _blocks()

    assert len(blocks) == 10, f"every access log is checked: {[name for name, _ in blocks]}"
    for name, rules in blocks:
        assert "request>uri" in rules, name
        assert rules.get("resp_headers>Location") == rules["request>uri"], f"{name}: Location is not redacted"
