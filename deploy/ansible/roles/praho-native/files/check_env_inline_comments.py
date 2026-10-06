#!/usr/bin/env python3
"""Refuse a .env file in which a comment would become part of a value.

The native deploy hands one .env file to several readers. bash and python-dotenv end a value where a
`#` starts a comment, but systemd's EnvironmentFile= and the deploy's own parsing keep the comment in
the value. `DJANGO_SETTINGS_MODULE=config.settings.staging  # note` then names a module that does not
exist. So any line where the readers would disagree is refused:

- a `#` that starts a word outside quotes, which is the shell's comment rule (`KEY=value  # note`,
  `KEY=   # note`, `KEY="quoted"  # note`); and
- a `#` straight after a closing quote (`KEY="quoted"# note`), which systemd glues onto the value; and
- a line ending in an unescaped backslash, which systemd joins to the next line (where a comment can
  hide), while bash drops that comment and the deploy's own parsing keeps the backslash.

A `#` inside quotes, or inside a word (`feature#12`, a URL fragment), is part of the value. Backslash
escapes are honoured, outside quotes and inside double quotes. Like systemd, the check allows
whitespace around the key (`KEY = value`).

Usage: check_env_inline_comments.py ENV_FILE
Exit 0 when clean; 1 when lines must change, printed as `line:KEY`, never the value, because the file
holds secrets; 2 when the file cannot be read.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_ASSIGNMENT = re.compile(r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=(.*)$")


def has_inline_comment(value: str) -> bool:
    """Whether readers would disagree on where this raw value ends."""
    quote = ""  # the open quote, or "" outside quotes
    word_start = True  # only unquoted whitespace since the value began or the last word ended
    after_quote = False  # the previous character closed a quote
    escaped = False
    for char in value:
        if escaped:
            escaped = word_start = after_quote = False
            continue
        if quote:
            if char == "\\" and quote == '"':
                escaped = True
            elif char == quote:
                quote, after_quote = "", True
            continue
        if char == "#" and (word_start or after_quote):
            return True
        if char == "\\":
            escaped = True
        elif char in "\"'":
            quote = char
        word_start = char in " \t"
        after_quote = False
    return False


def continues_line(value: str) -> bool:
    """Whether the value ends in an unescaped backslash, which joins it to the next line."""
    return (len(value) - len(value.rstrip("\\"))) % 2 == 1


def offending_lines(text: str) -> list[str]:
    """`line:KEY` for every assignment that readers would end in different places."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = _ASSIGNMENT.match(line)
        if match and (has_inline_comment(match.group(2)) or continues_line(match.group(2))):
            found.append(f"{number}:{match.group(1)}")
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 2:  # noqa: PLR2004  # the program name and one file
        print("usage: check_env_inline_comments.py ENV_FILE", file=sys.stderr)
        return 2
    path = Path(argv[1])
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        print(f"cannot read {path}: {error.strerror}", file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        print(f"cannot read {path}: not valid UTF-8", file=sys.stderr)
        return 2
    found = offending_lines(text)
    if found:
        print(f"{path} has a comment after a value, or a value continued with a trailing backslash,")
        print("on these lines (line:KEY). systemd and the deploy would read them differently from bash.")
        print("Move each comment onto its own line, and keep each value on one line:")
        print("\n".join(found))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
