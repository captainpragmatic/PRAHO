#!/usr/bin/env python3
"""One unprivileged marker, confined to this disposable VM's exact lab user."""

import json
import os
import pwd
import re
import sys
from pathlib import Path
from uuid import UUID


def main() -> None:
    request = json.loads(sys.stdin.read(4097))
    run = str(UUID(request["run"]))
    if Path("/root/praho-native-lab-owner").read_text().strip() != run:
        raise ValueError("The native VM is not owned by this acceptance run")
    username = "nat" + UUID(run).hex[:10]
    if request.get("username") != username or re.fullmatch(r"nat[0-9a-f]{10}", username) is None:
        raise ValueError("Only the exact native fixture user is allowed")
    identity = pwd.getpwnam(username)
    if identity.pw_uid == 0 or identity.pw_gid == 0 or identity.pw_dir != "/home/" + username:
        raise ValueError("The native fixture has no independent tenant identity")
    os.setgroups([])
    os.setgid(identity.pw_gid)
    os.setuid(identity.pw_uid)
    root = Path(identity.pw_dir) / "public_html"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("The native fixture document root is not an ordinary directory")
    marker = root / "praho-native-acceptance.txt"
    if request.get("action") == "write":
        value = request["value"]
        if value not in {"before-" + run, "after-" + run}:
            raise ValueError("Only fixed native fixture markers are accepted")
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as target:
            target.write(value)
    elif request.get("action") != "read":
        raise ValueError("Unsupported native marker action")
    descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as source:
        value = source.read(100)
    print(json.dumps({"value": value, "uid": os.getuid(), "gid": os.getgid()}))


if __name__ == "__main__":
    main()
