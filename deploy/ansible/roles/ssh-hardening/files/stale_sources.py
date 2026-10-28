"""Print, as JSON, the sources of SSH firewall rules that the allowlist no longer names."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys

# One stored rule per line, e.g. "ufw allow from 192.0.2.10 to any port 9876 proto tcp".
RULE = re.compile(r"^ufw allow from (\S+) to any port (\d+) proto tcp$")


def stale_sources(added: str, port: int, allowed: list[str]) -> list[str]:
    wanted = {ipaddress.ip_network(cidr, strict=True) for cidr in allowed}
    stale = []
    for line in added.splitlines():
        match = RULE.fullmatch(line.strip())
        if match and int(match.group(2)) == port and ipaddress.ip_network(match.group(1), strict=False) not in wanted:
            stale.append(match.group(1))
    return stale


def main() -> int:
    port, allowed = int(sys.argv[1]), json.loads(sys.argv[2])
    added = subprocess.run(["/usr/sbin/ufw", "show", "added"], capture_output=True, text=True, check=True).stdout
    print(json.dumps(stale_sources(added, port, allowed)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
