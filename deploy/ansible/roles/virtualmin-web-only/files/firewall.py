"""Converge UFW while a token-owned recovery snapshot protects administrative access."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from time import monotonic

BASE = Path("/var/lib/praho-firewall")
LOCK = Path("/run/praho-ssh-transition.lock")
CONFIG_FILES = [Path("/etc/default/ufw")] + [
    Path("/etc/ufw") / name
    for name in (
        "ufw.conf",
        "before.rules",
        "before6.rules",
        "after.rules",
        "after6.rules",
        "user.rules",
        "user6.rules",
        "before.init",
        "after.init",
    )
]
VENDOR = Path("/usr/share/ufw/iptables")
DEFAULTS = Path("/etc/default/ufw")
MAX_PORT = 65535
PUBLIC_RULE_WORDS = 3
ADMIN_RULE_WORDS = 10
HOOK_FILES = [Path("/etc/ufw") / name for name in ("before.init", "after.init")]
COMMAND_DEADLINE: float | None = None
ACTIVATION_BUDGET_SECONDS = 120


def run(argv: list[str]) -> str:
    timeout = 30 if COMMAND_DEADLINE is None else min(30, COMMAND_DEADLINE - monotonic())
    if timeout <= 0:
        raise TimeoutError("Firewall activation exceeded its recovery-safe command budget")
    return subprocess.run(  # noqa: S603 -- internal fixed commands only
        argv,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
    ).stdout


@contextmanager
def command_budget() -> Iterator[None]:
    global COMMAND_DEADLINE  # noqa: PLW0603 -- process-local deadline for this activation only
    previous = COMMAND_DEADLINE
    COMMAND_DEADLINE = monotonic() + ACTIVATION_BUDGET_SECONDS
    try:
        yield
    finally:
        COMMAND_DEADLINE = previous


def atomic(path: Path, content: bytes, mode: int = 0o600) -> None:
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".praho-firewall-")
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(content)
            target.flush()
            os.fchmod(target.fileno(), mode)
            os.fsync(target.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def snapshot(token: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}", token):
        raise ValueError("Invalid firewall transition token")
    return BASE / token


@contextmanager
def phase(token: str) -> Iterator[None]:
    with (snapshot(token) / "phase.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def owned(token: str) -> bool:
    return (LOCK / "owner").exists() and (LOCK / "owner").read_text() == token


def release(token: str) -> None:
    if owned(token):
        (LOCK / "owner").unlink()
        LOCK.rmdir()


def begin(token: str) -> None:
    target = snapshot(token)
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    LOCK.mkdir(mode=0o700)
    try:
        atomic(LOCK / "owner", token.encode())
        target.mkdir(mode=0o700)
        files = {}
        for path in CONFIG_FILES:
            if path.is_symlink():
                raise ValueError("Symlink in firewall configuration requires inspection")
            files[str(path)] = {
                "content": base64.b64encode(path.read_bytes()).decode() if path.exists() else None,
                "mode": path.stat().st_mode & 0o777 if path.exists() else 0o600,
            }
        atomic(
            target / "metadata.json",
            json.dumps(
                {
                    "files": files,
                    "active": "Status: active" in run(["ufw", "status"]),
                    "filters": {exe: run([exe + "-save", "-t", "filter"]) for exe in ("iptables", "ip6tables")},
                }
            ).encode(),
        )
        atomic(target / "state", b"prepared")
    except (OSError, ValueError, subprocess.SubprocessError):
        release(token)
        raise


def baseline(source: str) -> str:
    """Preserve vendor DHCP/ICMP exceptions, not mDNS/UPnP application listeners."""
    return "\n".join(line for line in source.splitlines() if not re.search(r"--dport (5353|1900)\b", line)) + "\n"


def obsolete_rules(status: str, networks: list[str], port: int) -> list[int]:
    allowed = {ipaddress.ip_network(network, strict=True) for network in networks}
    obsolete = []
    for line in status.splitlines():
        numbered = re.match(r"^\[\s*(\d+)\]\s+(.+)$", line.strip())
        if not numbered:
            continue
        rule = re.match(r"^(\d+)/tcp(?: \(v6\))?\s+ALLOW IN\s+(.+?)(?:\s+#.*)?$", numbered[2])
        keep = False
        if rule:
            source = re.sub(r"\s*\(v6\)$", "", rule[2]).strip()
            if rule[1] in {"80", "443"} and source == "Anywhere":
                keep = True
            elif rule[1] in {str(port), "10000"}:
                with suppress(ValueError):
                    keep = ipaddress.ip_network(source, strict=True) in allowed
        if not keep:
            obsolete.append(int(numbered[1]))
    return sorted(obsolete, reverse=True)


def fingerprint() -> str:
    digest = hashlib.sha256()
    for path in CONFIG_FILES:
        digest.update(str(path).encode() + b"\0")
        if path.exists():
            digest.update(str(path.stat().st_mode & 0o777).encode() + b"\0" + path.read_bytes())
        else:
            digest.update(b"absent")
    return digest.hexdigest()


def delete_command(rule: list[str]) -> list[str]:
    if rule[0] == "route":
        return ["ufw", "--force", "route", "delete", *rule[1:]]
    return ["ufw", "--force", "delete", *rule]


def foreign_input_rules(saved: str, *, ipv6: bool) -> list[str]:
    """Classify only INPUT; foreign routing/NAT policy belongs to its existing owner."""
    prefix = "ufw6" if ipv6 else "ufw"
    jumps = {
        ("-A", "INPUT", "-j", f"{prefix}-{chain}-input")
        for chain in ("before-logging", "before", "after", "after-logging", "reject", "track")
    }
    accepted = jumps | {("-A", "INPUT", "-i", "lo", "-j", "ACCEPT")}
    for module, option in (("conntrack", "--ctstate"), ("state", "--state")):
        for states in ("RELATED,ESTABLISHED", "ESTABLISHED,RELATED"):
            accepted.add(("-A", "INPUT", "-m", module, option, states, "-j", "ACCEPT"))
    foreign = [
        line for line in saved.splitlines() if line.startswith("-A INPUT ") and tuple(shlex.split(line)) not in accepted
    ]
    # A pristine ACCEPT chain is the normal inactive-UFW baseline. A foreign default
    # DROP policy needs its owner's review even if its few exceptions look familiar.
    if not any(tuple(shlex.split(line)) in jumps for line in saved.splitlines()):
        foreign.extend(line for line in saved.splitlines() if line.startswith(":INPUT DROP "))
    return foreign


def obsolete_commands(added: str, networks: list[str], port: int) -> list[list[str]]:
    """Inspect saved rules even when UFW is inactive; never enable stale application allows."""
    allowed = {ipaddress.ip_network(value, strict=True) for value in networks}
    result = []
    for line in added.splitlines():
        words = shlex.split(line)
        if (
            len(words) < PUBLIC_RULE_WORDS
            or words[0] != "ufw"
            or words[1] not in {"allow", "deny", "reject", "limit", "route"}
        ):
            continue
        original = words[1:]
        if "comment" in words:
            words = words[: words.index("comment")]
        keep = words[1:3] in [["allow", "80/tcp"], ["allow", "443/tcp"]] and len(words) == PUBLIC_RULE_WORDS
        if (
            words[1] == "allow"
            and len(words) == ADMIN_RULE_WORDS
            and words[2] == "from"
            and words[4:7] == ["to", "any", "port"]
            and words[8:] == ["proto", "tcp"]
        ):
            with suppress(ValueError):
                keep = words[7] in {str(port), "10000"} and ipaddress.ip_network(words[3], strict=True) in allowed
        if not keep:
            result.append(original)
    return result


def add_allowed(networks: list, port: int) -> None:
    for public in ("80", "443"):
        run(["ufw", "allow", public + "/tcp"])
    for network in networks:
        for administrative in (str(port), "10000"):
            run(["ufw", "allow", "from", str(network), "to", "any", "port", administrative, "proto", "tcp"])


def guard_name(token: str) -> str:
    snapshot(token)
    return "praho-" + token[:20]  # Both xtables families limit user chain names to 28 bytes.


def guard_rules(networks: list, port: int, *, ipv6: bool) -> list[list[str]]:
    """Return approved traffic to UFW; keep all other INPUT closed during its restart."""
    rules = [["-i", "lo", "-j", "RETURN"], ["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"]]
    rules.extend(["-p", "tcp", "--dport", public, "-j", "RETURN"] for public in ("80", "443"))
    for network in networks:
        if isinstance(network, ipaddress.IPv6Network) == ipv6:
            rules.extend(
                ["-s", str(network), "-p", "tcp", "--dport", administrative, "-j", "RETURN"]
                for administrative in sorted({str(port), "10000"})
            )
    if ipv6:
        rules.append(
            ["-s", "fe80::/10", "-d", "fe80::/10", "-p", "udp", "--sport", "547", "--dport", "546", "-j", "RETURN"]
        )
        for kind in (
            1,
            2,
            3,
            4,
            128,
            129,
            130,
            131,
            132,
            133,
            134,
            135,
            136,
            141,
            142,
            143,
            144,
            145,
            146,
            147,
            148,
            149,
            151,
            152,
            153,
        ):
            control = ["-p", "ipv6-icmp", "--icmpv6-type", str(kind)]
            if kind in {130, 131, 132, 143, 151, 152, 153}:
                control += ["-s", "fe80::/10"]
            if kind in {133, 134, 135, 136, 141, 142, 148, 149, 151, 152, 153}:
                control += ["-m", "hl", "--hl-eq", "1" if kind in {151, 152, 153} else "255"]
            rules.append([*control, "-j", "RETURN"])
    else:
        rules.append(["-p", "udp", "--sport", "67", "--dport", "68", "-j", "RETURN"])
        rules.extend(["-p", "icmp", "--icmp-type", str(kind), "-j", "RETURN"] for kind in (3, 8, 11, 12))
    return [*rules, ["-j", "DROP"]]


def normalized_rule(words: list[str]) -> tuple:
    """Ignore xtables' implicit transport modules and option ordering, never conditions."""
    if len(words) % 2:
        raise RuntimeError("Unknown effective INPUT policy condition")
    options = []
    for index in range(0, len(words), 2):
        key, value = words[index : index + 2]
        if key == "--comment" or (key == "-m" and value in {"tcp", "udp", "icmp", "icmp6", "comment"}):
            continue
        if key in {"-s", "-d"}:
            value = str(ipaddress.ip_network(value, strict=False))
        if key == "-p" and value == "icmpv6":
            value = "ipv6-icmp"
        options.append((key, value))
    return tuple(sorted(options))


def filter_chains(saved: str) -> dict[str, list[list[str]]]:
    chains: dict[str, list[list[str]]] = {}
    for line in saved.splitlines():
        if line.startswith(":"):
            chains.setdefault(line.split()[0][1:], [])
        elif line.startswith("-A "):
            words = shlex.split(line)
            chains.setdefault(words[1], []).append(words[2:])
    return chains


def ensure_guard(token: str, request: dict) -> None:
    name = guard_name(token)
    networks = [ipaddress.ip_network(value, strict=True) for value in request["cidrs"]]
    for executable, ipv6 in (("iptables", False), ("ip6tables", True)):
        saved = run([executable + "-save", "-t", "filter"])
        chains = filter_chains(saved)
        wanted = guard_rules(networks, request["port"], ipv6=ipv6)
        attached = ["-j", name] in chains.get("INPUT", [])
        if attached:
            if chains["INPUT"][0] != ["-j", name] or [normalized_rule(rule) for rule in chains[name]] != [
                normalized_rule(rule) for rule in wanted
            ]:
                raise RuntimeError("The owned INPUT guard changed; leave recovery armed for inspection")
            continue
        run([executable, "-w", "-F" if name in chains else "-N", name])
        for rule in wanted:
            run([executable, "-w", "-A", name, *rule])
        # A partial construction never attaches an unfinished (permissive) guard.
        run([executable, "-w", "-I", "INPUT", "1", "-j", name])


def remove_guard(token: str) -> None:
    name = guard_name(token)
    for executable in ("iptables", "ip6tables"):
        chains = filter_chains(run([executable + "-save", "-t", "filter"]))
        if ["-j", name] in chains.get("INPUT", []):
            run([executable, "-w", "-D", "INPUT", "-j", name])
        if name in chains:
            run([executable, "-w", "-F", name])
            run([executable, "-w", "-X", name])


def verify_guarded_filter(saved: str, token: str, request: dict, *, ipv6: bool) -> None:
    """Attest the effective INPUT graph before discarding its independent safety guard."""
    name = guard_name(token)
    chains = filter_chains(saved)
    networks = [ipaddress.ip_network(value, strict=True) for value in request["cidrs"]]
    wanted = guard_rules(networks, request["port"], ipv6=ipv6)
    without_guard = "\n".join(line for line in saved.splitlines() if line != f"-A INPUT -j {name}")
    if (
        not any(line.startswith(":INPUT DROP ") for line in saved.splitlines())
        or (chains.get("INPUT") or [[]])[0] != ["-j", name]
        or foreign_input_rules(without_guard, ipv6=ipv6)
        or [normalized_rule(rule) for rule in chains.get(name, [])] != [normalized_rule(rule) for rule in wanted]
    ):
        raise RuntimeError("Effective INPUT policy or transition guard could not be verified")
    acceptable = {normalized_rule([*rule[:-1], "ACCEPT"]) for rule in wanted[:-1]}
    grants = sorted(normalized_rule([*rule[:-1], "ACCEPT"]) for rule in wanted if "tcp" in rule)
    user = "ufw6-user-input" if ipv6 else "ufw-user-input"
    before = "ufw6-before-input" if ipv6 else "ufw-before-input"
    if (
        ["-j", before] not in chains["INPUT"]
        or ["-j", user] not in chains.get(before, [])
        or sorted(normalized_rule(rule) for rule in chains.get(user, [])) != grants
    ):
        raise RuntimeError("Effective administrative/web policy grants do not match the reviewed policy")
    prefix = "ufw6" if ipv6 else "ufw"
    owned_chains = {
        prefix + "-" + suffix
        for suffix in (
            "before-logging-input",
            "before-input",
            "after-input",
            "after-logging-input",
            "reject-input",
            "track-input",
            "logging-deny",
            "logging-allow",
            "not-local",
            "user-input",
            "user-logging-input",
            "skip-to-policy-input",
        )
    }
    pending, visited = ["INPUT"], set()
    while pending:
        chain = pending.pop()
        if chain in visited:
            continue
        visited.add(chain)
        for rule in chains[chain]:
            if "-g" in rule or rule.count("-j") != 1:
                raise RuntimeError("Unknown effective INPUT policy jump")
            target = rule[rule.index("-j") + 1]
            if target == "ACCEPT":
                if normalized_rule(rule) not in acceptable:
                    raise RuntimeError("Effective INPUT policy contains an unreviewed ACCEPT")
            elif target in {"DROP", "REJECT", "RETURN", "LOG", "NFLOG"}:
                continue
            elif target in chains and (target == name or target in owned_chains):
                pending.append(target)
            else:
                raise RuntimeError("Unknown effective INPUT policy chain")


def safe_defaults() -> None:
    """Avoid both native UFW paths that flush unrelated tables or the INPUT guard."""
    original = DEFAULTS.read_text()
    updated = original
    required = {"MANAGE_BUILTINS": "no", "IPV6": "yes" if Path("/proc/net/if_inet6").exists() else "no"}
    for key, value in required.items():
        updated, count = re.subn(r"(?m)^\s*(?:export\s+)?" + key + r"=.*$", key + "=" + value, updated)
        if not count:
            updated += "\n" + key + "=" + value + "\n"
    if updated != original:
        atomic(DEFAULTS, updated.encode(), DEFAULTS.stat().st_mode & 0o777)


def configure_baselines() -> None:
    for name in ("before.rules", "before6.rules", "after.rules", "after6.rules"):
        path = Path("/etc/ufw") / name
        content = baseline((VENDOR / name).read_text()).encode()
        if path.read_bytes() != content:
            atomic(path, content, 0o640)
    defaults = Path("/etc/default/ufw")
    wanted = "yes" if Path("/proc/net/if_inet6").exists() else "no"
    original = defaults.read_text()
    updated = re.sub(r"(?m)^IPV6=.*$", "IPV6=" + wanted, original)
    if updated == original and not re.search(r"(?m)^IPV6=", original):
        updated += "\nIPV6=" + wanted + "\n"
    if updated != original:
        atomic(defaults, updated.encode(), 0o644)


def activate(token: str, request: dict) -> None:  # noqa: C901 -- ordered access transition keeps recovery boundaries explicit
    networks = [ipaddress.ip_network(value, strict=True) for value in request["cidrs"]]
    connection = os.environ["SSH_CONNECTION"].split()
    port = int(connection[3])
    peer = ipaddress.ip_address(connection[0])
    if (
        not networks
        or any(network.prefixlen == 0 for network in networks)
        or not any(peer in network for network in networks)
    ):
        raise ValueError("Current SSH peer must belong to a nonempty administrative allowlist")
    if not 1 <= port <= MAX_PORT:
        raise ValueError("Invalid current SSH port")
    hooks = HOOK_FILES
    reviewed_hooks = request.get("reviewed_hooks", {})
    for path in hooks:
        if (
            path.exists()
            and os.access(path, os.X_OK)
            and (
                not isinstance(reviewed_hooks, dict)
                or reviewed_hooks.get(str(path)) != hashlib.sha256(path.read_bytes()).hexdigest()
            )
        ):
            raise ValueError("Executable firewall reload hooks require explicit review before convergence")
    with phase(token), command_budget():
        target = snapshot(token)
        if not owned(token) or (target / "state").read_text() != "prepared":
            raise RuntimeError("Firewall transition no longer owns access")
        for executable, ipv6 in (("iptables-save", False), ("ip6tables-save", True)):
            saved = run([executable, "-t", "filter"])
            if foreign_input_rules(saved, ipv6=ipv6):
                raise ValueError("Foreign INPUT rules require manual reviewed preparation before convergence")
            if guard_name(token) in filter_chains(saved):
                raise ValueError("Transition guard chain already exists; manual inspection is required")
        # Recovery must not execute unknown reload hooks when preflight rejected before mutation.
        before = fingerprint()
        active = "Status: active" in run(["ufw", "status"])
        request = {"cidrs": [str(network) for network in networks], "port": port}
        atomic(target / "guard.json", json.dumps(request).encode())
        atomic(target / "state", b"guarding")
        ensure_guard(token, request)
        safe_defaults()
        atomic(target / "state", b"pending")
        for path in hooks:
            if path.exists() and os.access(path, os.X_OK):
                path.chmod(path.stat().st_mode & ~0o111)
        add_allowed(networks, port)
        configure_baselines()
        # Add again after enabling IPv6 support, so both families receive the policy.
        add_allowed(networks, port)
        for rule in obsolete_commands(run(["ufw", "show", "added"]), [str(value) for value in networks], port):
            run(delete_command(rule))
        add_allowed(networks, port)
        run(["ufw", "default", "deny", "incoming"])
        run(["ufw", "default", "allow", "outgoing"])
        run(["ufw", "--force", "enable"])
        run(["ufw", "reload"])
        for executable, ipv6 in (("iptables-save", False), ("ip6tables-save", True)):
            verify_guarded_filter(run([executable, "-t", "filter"]), token, request, ipv6=ipv6)
        print(json.dumps({"changed": not active or fingerprint() != before}))


def commit(token: str) -> None:
    with phase(token):
        target = snapshot(token)
        if not owned(token) or (target / "state").read_text() != "pending":
            raise RuntimeError("Firewall recovery already ran or ownership changed")
        request = json.loads((target / "guard.json").read_text())
        for executable, ipv6 in (("iptables-save", False), ("ip6tables-save", True)):
            verify_guarded_filter(run([executable, "-t", "filter"]), token, request, ipv6=ipv6)
        remove_guard(token)
        atomic(target / "state", b"committed")
        release(token)


def rollback(token: str) -> None:
    with phase(token):
        target = snapshot(token)
        if not owned(token) or (target / "state").read_text() in {"committed", "rolled-back"}:
            return
        if (target / "state").read_text() == "prepared":
            atomic(target / "state", b"rolled-back")
            release(token)
            return
        metadata = json.loads((target / "metadata.json").read_text())
        guarding = (target / "state").read_text() == "guarding"
        if not guarding and (target / "guard.json").exists():
            ensure_guard(token, json.loads((target / "guard.json").read_text()))
        for name, saved in metadata["files"].items():
            path = Path(name)
            if saved["content"] is None:
                path.unlink(missing_ok=True)
            else:
                # Restoring an executable hook must never execute its old kernel side effects.
                mode = saved["mode"] & ~0o111 if path in HOOK_FILES else saved["mode"]
                atomic(path, base64.b64decode(saved["content"]), mode)
        if not guarding:
            if DEFAULTS.exists():
                safe_defaults()
            run(["ufw", "reload"] if metadata["active"] else ["ufw", "--force", "disable"])
            for executable, original in metadata["filters"].items():
                current = run([executable + "-save", "-t", "filter"])
                if input_projection(current, guard_name(token)) != input_projection(original):
                    raise RuntimeError(
                        "Restored INPUT policy differs from the saved effective policy; recovery stays armed"
                    )
        # Restore original defaults/hook bytes and modes after the safe native reload, without another reload.
        for path in [DEFAULTS, *HOOK_FILES]:
            saved = metadata["files"].get(str(path))
            if saved and saved["content"] is not None:
                atomic(path, base64.b64decode(saved["content"]), saved["mode"])
        remove_guard(token)
        atomic(target / "state", b"rolled-back")
        release(token)


def input_projection(saved: str, guard: str | None = None) -> tuple:
    """Compare only effective INPUT; UFW may leave harmless empty primary chains on stop."""
    chains = filter_chains(saved)
    policy = next((line.split()[1] for line in saved.splitlines() if line.startswith(":INPUT ")), None)
    pending, visited, rows = ["INPUT"], set(), []
    while pending:
        chain = pending.pop()
        if chain in visited:
            continue
        visited.add(chain)
        for rule in chains.get(chain, []):
            target = rule[rule.index("-j") + 1] if "-j" in rule else None
            if target == guard or (target in chains and not chains[target]):
                continue
            rows.append((chain, tuple(rule)))
            if target in chains:
                pending.append(target)
    return policy, tuple(rows)


if __name__ == "__main__":
    operation, transition = sys.argv[1:3]
    if operation == "activate":
        activate(transition, json.loads(sys.stdin.read(65536)))
    elif operation == "begin":
        begin(transition)
    elif operation == "commit":
        commit(transition)
    elif operation == "rollback":
        rollback(transition)
    else:
        raise ValueError("Unknown firewall operation")
