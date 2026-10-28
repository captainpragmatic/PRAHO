"""Print, as JSON, the SSH firewall rules (source and protocol) that the allowlist no longer names."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys

# One stored rule per line, e.g. "ufw allow from 192.0.2.10 to any port 9876 proto tcp comment 'staff'".
RULE = re.compile(r"^ufw allow from (\S+) to any port (\d+)(?: proto (tcp|any))?(?: comment .*)?$")


def stale_sources(added: str, port: int, allowed: list[str]) -> list[dict[str, str]]:
    wanted = {ipaddress.ip_network(cidr, strict=True) for cidr in allowed}
    stale = []
    for line in added.splitlines():
        match = RULE.fullmatch(line.strip())
        if not match or int(match.group(2)) != port:
            continue
        source = match.group(1)
        # "from any" opens the port to everyone, so it is never on the list.
        if source == "any" or ipaddress.ip_network(source, strict=False) not in wanted:
            stale.append({"source": source, "proto": match.group(3) or "any"})
    return stale


def main() -> int:
    port, allowed = int(sys.argv[1]), json.loads(sys.argv[2])
    added = subprocess.run(["/usr/sbin/ufw", "show", "added"], capture_output=True, text=True, check=True).stdout
    print(json.dumps(stale_sources(added, port, allowed)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
