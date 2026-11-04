"""Host role refuses unowned policy and prevents package bootstrap network work."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from jinja2 import Environment

from apps.provisioning.crowdsec_policy import GATEWAY_SUDO

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "deploy/ansible/roles/crowdsec"


def load_helper(name: str):
    spec = importlib.util.spec_from_file_location(name, ROLE / "files" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "arguments",
    [
        ["hub", "update"],
        ["--debug", "hub", "upgrade"],
        ["setup", "unattended"],
        ["-c", "/etc/crowdsec/config.yaml", "parsers", "install", "crowdsecurity/sshd-logs"],
        ["collections", "install", "crowdsecurity/linux"],
        ["capi", "register"],
        ["console", "enroll", "placeholder"],
    ],
)
def test_ordinary_cli_cannot_refresh_mutable_hub_or_enroll(arguments: list[str]) -> None:
    guard = load_helper("cli_guard")
    assert guard.forbidden_operation(arguments, simulation=False) is not None


def test_cli_simulation_refuses_creates_but_keeps_repair_available() -> None:
    guard = load_helper("cli_guard")
    assert guard.forbidden_operation(["decisions", "add", "--ip", "192.0.2.9"], simulation=True)
    assert guard.forbidden_operation(["decisions", "add", "--ip", "192.0.2.9"], simulation=False) is None
    for arguments in (["decisions", "delete", "--id", "1"], ["allowlists", "add", "praho-inventory", "192.0.2.0/24"]):
        assert guard.forbidden_operation(arguments, simulation=True) is None


def test_only_exact_maintainer_invocations_can_be_skipped() -> None:
    guard = load_helper("cli_guard")
    assert guard.maintainer_skip(["hub", "update"], package="crowdsec", guard_present=True)
    assert guard.maintainer_skip(["setup", "unattended"], package="crowdsec", guard_present=True)
    assert not guard.maintainer_skip(["hub", "update"], package="other", guard_present=True)
    assert not guard.maintainer_skip(["hub", "update"], package="crowdsec", guard_present=False)
    assert not guard.maintainer_skip(
        ["parsers", "install", "crowdsecurity/sshd-logs"], package="crowdsec", guard_present=True
    )
    assert not guard.maintainer_skip(["capi", "register"], package="crowdsec", guard_present=True)


def test_new_firewall_uses_owned_dual_stack_input_hooks_and_protection_first() -> None:
    firewall = load_helper("firewall")
    config = {"simulation": True, "protected_cidrs": ["192.0.2.0/24", "fd00:767::/64"]}
    result = firewall.compile_update(config, {"ip": None, "ip6": None})
    assert "table ip praho_crowdsec4" in result and "table ip6 praho_crowdsec6" in result
    assert "flags interval,timeout" in result
    assert "type filter hook input priority -10; policy accept" in result
    assert result.index("ip saddr @protected return") < result.index("ip saddr @bans drop")
    assert "flush ruleset" not in result and "forward" not in result and "ufw" not in result


def test_firewall_rejects_unknown_owned_schema_before_any_mutation() -> None:
    firewall = load_helper("firewall")
    bad = {
        "nftables": [
            {"table": {"family": "ip", "name": "praho_crowdsec4"}},
            {"chain": {"family": "ip", "table": "praho_crowdsec4", "name": "foreign", "hook": "forward"}},
        ]
    }
    with pytest.raises(ValueError, match="owned firewall"):
        firewall.compile_update({"simulation": False, "protected_cidrs": ["192.0.2.0/24"]}, {"ip": bad, "ip6": None})


@pytest.mark.parametrize(
    "config",
    [
        {"simulation": "true", "protected_cidrs": ["192.0.2.0/24"]},
        {"simulation": True, "protected_cidrs": ["0.0.0.0/0"]},
        {"simulation": True, "protected_cidrs": ["192.0.2.4/24"]},
        {"simulation": True, "protected_cidrs": []},
    ],
)
def test_firewall_rejects_ambiguous_or_unbounded_inventory(config: dict[str, object]) -> None:
    firewall = load_helper("firewall")
    with pytest.raises(ValueError):
        firewall.compile_update(config, {"ip": None, "ip6": None})


def test_installation_reconvergence_keeps_uuid_and_never_recreates_missing_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enroll = load_helper("enroll")
    monkeypatch.setattr(enroll, "STATE", tmp_path / "installation.json")
    monkeypatch.setattr(enroll, "CONFIG", tmp_path / "config.json")
    monkeypatch.setattr(enroll, "DATABASE", tmp_path / "crowdsec.db")
    calls = []

    def register_marker(name: str) -> None:
        calls.append(name)
        with closing(sqlite3.connect(enroll.DATABASE)) as connection, connection:
            connection.execute("CREATE TABLE machines (machine_id TEXT NOT NULL)")
            connection.execute("INSERT INTO machines VALUES (?)", [name])

    policy = {"simulation": True, "protected_cidrs": ["192.0.2.0/24"]}
    first = enroll.ensure_installation(policy, register_marker)
    second = enroll.ensure_installation(policy, register_marker)
    assert first["installation_id"] == second["installation_id"]
    assert second["changed"] is False and len(calls) == 1
    config = json.loads(enroll.CONFIG.read_text())
    assert config["database_witness"] == {
        "device": enroll.DATABASE.stat().st_dev,
        "inode": enroll.DATABASE.stat().st_ino,
    }
    with closing(sqlite3.connect(enroll.DATABASE)) as connection, connection:
        connection.execute("DELETE FROM machines")
    with pytest.raises(ValueError, match="reenrollment"):
        enroll.ensure_installation(policy, register_marker)
    assert len(calls) == 1


def test_installation_database_replacement_cannot_reuse_old_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enroll = load_helper("enroll")
    monkeypatch.setattr(enroll, "STATE", tmp_path / "installation.json")
    monkeypatch.setattr(enroll, "CONFIG", tmp_path / "config.json")
    monkeypatch.setattr(enroll, "DATABASE", tmp_path / "crowdsec.db")

    def register_marker(name: str) -> None:
        with closing(sqlite3.connect(enroll.DATABASE)) as connection, connection:
            connection.execute("CREATE TABLE machines (machine_id TEXT NOT NULL)")
            connection.execute("INSERT INTO machines VALUES (?)", [name])

    policy = {"simulation": True, "protected_cidrs": ["192.0.2.0/24"]}
    first = enroll.ensure_installation(policy, register_marker)
    replacement = tmp_path / "replacement.db"
    replacement.write_bytes(enroll.DATABASE.read_bytes())
    replacement.replace(enroll.DATABASE)
    before = enroll.CONFIG.read_bytes()
    with pytest.raises(ValueError, match="reenrollment"):
        enroll.ensure_installation(policy, register_marker)
    assert enroll.CONFIG.read_bytes() == before
    assert json.loads(enroll.STATE.read_text())["installation_id"] == first["installation_id"]


def test_inventory_allowlist_reconciles_its_own_list_and_preserves_staff_entries() -> None:
    allowlist = load_helper("allowlist")
    inventory = {
        "name": "praho-inventory",
        "console_managed": False,
        "items": [{"value": "192.0.2.0/24"}, {"value": "198.51.100.0/24"}],
    }
    staff = {"name": "praho-staff", "console_managed": False, "items": [{"value": "203.0.113.9"}]}
    calls = []

    def execute(arguments: list[str]) -> str:
        calls.append(arguments)
        if arguments[-2:] == ["allowlists", "list"]:
            return json.dumps([inventory, staff])
        operation, name, *values = arguments[1:]
        assert name == "praho-inventory"
        if operation == "add":
            inventory["items"].extend({"value": value} for value in values)
        elif operation == "remove":
            inventory["items"] = [item for item in inventory["items"] if item["value"] not in values]
        else:
            raise AssertionError(arguments)
        return ""

    desired = ["192.0.2.0/24", "fd00:767::/64"]
    assert allowlist.sync_inventory(desired, execute) is True
    assert {item["value"] for item in inventory["items"]} == set(desired)
    assert staff["items"] == [{"value": "203.0.113.9"}]
    before = len(calls)
    assert allowlist.sync_inventory(desired, execute) is False
    assert len(calls) == before + 1


def test_inventory_allowlist_accepts_native_zero_expiration_with_milliseconds() -> None:
    allowlist = load_helper("allowlist")
    data = [
        {
            "name": "praho-inventory",
            "console_managed": False,
            "items": [{"value": "192.0.2.0/24", "expiration": "0001-01-01T00:00:00.000Z"}],
        }
    ]
    calls = []

    def execute(arguments: list[str]) -> str:
        calls.append(arguments)
        return json.dumps(data)

    assert allowlist.sync_inventory(["192.0.2.0/24"], execute) is False
    assert len(calls) == 1


@pytest.mark.parametrize(
    "relative",
    [
        "etc/crowdsec/config.yaml.local",
        "etc/crowdsec/acquis.d/other.yaml",
        "etc/crowdsec/parsers/s01-parse/other.yaml",
        "etc/systemd/system/crowdsec.service.d/override.conf",
    ],
)
def test_adoption_refuses_unreviewed_configuration_without_deleting_it(
    relative: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight = load_helper("preflight")
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    foreign = tmp_path / relative
    foreign.parent.mkdir(parents=True)
    foreign.write_text("unreviewed configuration\n")
    with pytest.raises(ValueError, match="unreviewed"):
        preflight.check_configuration([])
    assert foreign.read_text() == "unreviewed configuration\n"


def test_adoption_recognizes_its_permanent_hub_timer_mask(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    preflight = load_helper("preflight")
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    mask = tmp_path / "etc/systemd/system/crowdsec-hubupdate.timer"
    mask.parent.mkdir(parents=True)
    mask.symlink_to("/dev/null")
    preflight.check_configuration([])
    assert mask.is_symlink()


def test_role_sudoers_rendering_matches_reviewed_remote_contract() -> None:
    source = (ROLE / "templates/sudoers.j2").read_text()
    environment = Environment(trim_blocks=True, keep_trailing_newline=True, autoescape=False)  # noqa: S701 -- exact plaintext Ansible sudo configuration, no HTML
    assert environment.from_string(source).render(crowdsec_local_reader_user="") == GATEWAY_SUDO


@pytest.mark.parametrize(
    "command",
    [
        "decision",
        "collection",
        "parser",
        "scenario",
        "postoverflow",
        "contexts",
        "context",
        "appsec-configs",
        "appsec-config",
        "waf-configs",
        "appsec-rules",
        "appsec-rule",
        "waf-rules",
    ],
)
def test_cli_singular_aliases_keep_the_same_locked_policy(command: str) -> None:
    guard = load_helper("cli_guard")
    operation = "add" if command == "decision" else "install"
    assert guard.forbidden_operation([command, operation, "--help"], simulation=True)
    assert guard.forbidden_operation([command, "list"], simulation=True) is None
    if command == "decision":
        assert guard.forbidden_operation([command, "remove", "--id", "1"], simulation=True) is None
        assert guard.forbidden_operation([command, operation, "--ip", "192.0.2.9"], simulation=False) is None


@pytest.mark.parametrize(
    "arguments",
    [
        ["decisions", "--debug", "add", "--ip", "192.0.2.9"],
        ["decision", "--output", "json", "add"],
        ["hub", "--debug", "update"],
        ["parser", "-ojson", "install", "crowdsecurity/sshd-logs"],
        ["--config", "/etc/crowdsec/config.yaml", "decision", "--color=never", "import"],
        ["decisions", "--unknown", "add"],
        ["decisions", "--output"],
    ],
)
def test_cli_persistent_flags_cannot_hide_a_mutation(arguments: list[str]) -> None:
    assert load_helper("cli_guard").forbidden_operation(arguments, simulation=True)


@pytest.mark.parametrize(
    "arguments",
    [
        ["-o", "json", "decision", "--debug", "list"],
        ["hub", "--debug", "list"],
        ["parser", "--output=json", "inspect", "crowdsecurity/sshd-logs"],
        ["decision", "--color", "no", "remove", "--ip", "192.0.2.9"],
    ],
)
def test_cli_read_and_repair_paths_accept_persistent_flags(arguments: list[str]) -> None:
    assert load_helper("cli_guard").forbidden_operation(arguments, simulation=True) is None


@pytest.mark.parametrize("operation", ["enable", "disable"])
def test_cli_simulation_mode_changes_require_the_reviewed_role(operation: str) -> None:
    guard = load_helper("cli_guard")
    assert guard.forbidden_operation(["simulation", "--debug", operation, "--global"], simulation=False)
    assert guard.forbidden_operation(["simulation", "status"], simulation=True) is None


def test_applied_service_witnesses_are_bounded_private_and_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight = load_helper("preflight")
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    assert preflight.read_service_stamps() == {"engine": "", "bouncer": ""}
    state = tmp_path / "var/lib/praho-crowdsec"
    state.mkdir(parents=True)
    engine = state / "engine-applied.sha256"
    engine.write_text("a" * 64 + "\n")
    engine.chmod(0o600)
    monkeypatch.setattr(preflight, "TRUSTED_UID", engine.stat().st_uid)
    monkeypatch.setattr(preflight, "TRUSTED_GID", engine.stat().st_gid)
    assert preflight.read_service_stamps() == {"engine": "a" * 64 + "\n", "bouncer": ""}
    engine.write_text("malformed\n")
    assert preflight.read_service_stamps()["engine"] == ""
    engine.write_text("b" * 64 + "\n")
    engine.chmod(0o666)
    with pytest.raises(ValueError, match="applied service"):
        preflight.read_service_stamps()
    engine.unlink()
    secret = state / "unrelated-private-file"
    secret.write_text("private fixture data")
    engine.symlink_to(secret)
    with pytest.raises(ValueError, match="applied service"):
        preflight.read_service_stamps()
