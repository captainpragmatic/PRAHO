"""Pure native sender-map renderer; the lock-owning Virtualmin caller publishes the result."""

from __future__ import annotations

import json
import re
import sys
from typing import Any

MAX_DOMAINS = 5000
MAX_USERS = 10000
MAX_BYTES = 2 * 1024 * 1024
MAX_RESERVED_ZONES = 64
MAX_HOSTNAME = 253
MIN_LABELS = 2
MIN_UID = 1000
MAX_DOMAIN_USERS = 1000


def hostname(value: object) -> str:
    if not isinstance(value, str) or len(value) > MAX_HOSTNAME or len(value.split(".")) < MIN_LABELS:
        raise ValueError("invalid native domain")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")):
        raise ValueError("invalid native domain")
    return value


def identity(login: object, uid: object) -> tuple[str, int]:
    if not isinstance(login, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}", login):
        raise ValueError("invalid native login")
    if type(uid) is not int or not MIN_UID <= uid < 2**31 or login in {"root", "postfix"}:
        raise ValueError("invalid native UID")
    return login, uid


def render(rows: object, zones: object) -> bytes:
    if not isinstance(zones, list) or not zones or len(zones) > MAX_RESERVED_ZONES:
        raise ValueError("incomplete reserved zones")
    reserved = {hostname(zone) for zone in zones}
    if len(reserved) != len(zones) or not isinstance(rows, list) or len(rows) > MAX_DOMAINS:
        raise ValueError("incomplete native inventory")
    grants: dict[str, set[str]] = {"root": {"*"}, "postfix": {"*"}}
    logins: dict[str, int] = {}
    uids: dict[int, str] = {}
    domains = set()
    total = 0

    def bind(login: object, uid: object) -> str:
        login, uid = identity(login, uid)
        if (login in logins and logins[login] != uid) or (uid in uids and uids[uid] != login):
            raise ValueError("conflicting native identity")
        logins[login], uids[uid] = uid, login
        return login

    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid native inventory")
        domain = hostname(row.get("domain"))
        if domain in domains or type(row.get("enabled")) is not bool:
            raise ValueError("conflicting native domain")
        domains.add(domain)
        owner = bind(row.get("owner"), row.get("owner_uid"))
        users = row.get("users")
        if not isinstance(users, list) or len(users) > MAX_DOMAIN_USERS:
            raise ValueError("incomplete mailbox inventory")
        total += len(users)
        if total > MAX_USERS:
            raise ValueError("mailbox inventory exceeds bound")
        allowed = row["enabled"] and not any(domain == zone or domain.endswith("." + zone) for zone in reserved)
        if allowed:
            grants.setdefault(owner, set()).add("@" + domain)
        _user_grants(users, domain, bind, allowed, grants)
    result = "".join(login + " " + ",".join(sorted(values)) + "\n" for login, values in sorted(grants.items())).encode()
    if len(result) > MAX_BYTES:
        raise ValueError("map exceeds bound")
    return result


def _user_grants(users: list[Any], domain: str, bind: Any, allowed: bool, grants: dict[str, set[str]]) -> None:
    for user in users:
        if not isinstance(user, dict) or type(user.get("enabled")) is not bool:
            raise ValueError("invalid mailbox")
        login = bind(user.get("login"), user.get("uid"))
        email = user.get("email")
        if not isinstance(email, str) or not re.fullmatch(r"[A-Za-z0-9_.+%=-]{1,64}@" + re.escape(domain), email):
            raise ValueError("foreign mailbox")
        if allowed and user["enabled"]:
            grants.setdefault(login, set()).add(email)


def main() -> None:
    content = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise ValueError("inventory exceeds bound")
    data: dict[str, Any] = json.loads(content)
    output = render(data["domains"], data["reserved_zones"])
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    main()
