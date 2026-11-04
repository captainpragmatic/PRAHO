"""CrowdSec only owns the exact reviewed dual-stack INPUT schema."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from django.core.exceptions import ValidationError
from jinja2 import Environment

from apps.provisioning import crowdsec_policy as policy
from apps.provisioning.crowdsec_policy import verify_owned_firewall
from apps.provisioning.virtualmin_security_policy import SSH_CONFIG_DIGESTS, verify_evidence


def owned_firewall() -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for family, table, address_type, protected in (
        ("ip", "praho_crowdsec4", "ipv4_addr", "192.0.2.1"),
        ("ip6", "praho_crowdsec6", "ipv6_addr", "2001:db8::1"),
    ):
        identity = {"family": family, "table": table}
        entries += [
            {"table": {"family": family, "name": table}},
            {
                "chain": {
                    **identity,
                    "name": "input",
                    "type": "filter",
                    "hook": "input",
                    "prio": -10,
                    "policy": "accept",
                }
            },
            {
                "set": {
                    **identity,
                    "name": "protected",
                    "type": address_type,
                    "flags": ["interval"],
                    "elem": [protected],
                }
            },
            {"set": {**identity, "name": "bans", "type": address_type, "flags": ["interval", "timeout"]}},
        ]
        for name, action in (("protected", "return"), ("bans", "drop")):
            entries.append(
                {
                    "rule": {
                        **identity,
                        "chain": "input",
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"payload": {"protocol": family, "field": "saddr"}},
                                    "right": "@" + name,
                                }
                            },
                            {action: None},
                        ],
                    }
                }
            )
    return entries


PROTECTED = ["192.0.2.1/32", "2001:db8::1/128"]
ROOT = Path(__file__).resolve().parents[2]


def inspector():
    path = ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho-node-security-inspect.py"
    spec = importlib.util.spec_from_file_location("crowdsec_node_inspector", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_ruleset_metadata_stays_outside_owned_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    module = inspector()
    metadata = {"metainfo": {"version": "1.1.5", "release_name": "native fixture", "json_schema_version": 1}}
    foreign = {"set": {"family": "inet", "table": "unrelated", "name": "sentinel", "type": "ipv4_addr"}}
    native = {"nftables": [metadata, *owned_firewall(), foreign]}

    def observed(argv: list[str]) -> str:
        if argv[0] == "ip":
            return "[]"
        if "--version" in argv:
            return "iptables-save v1.8.11 (nf_tables)"
        assert argv[1:] == ["-t", "nat"]
        return "*nat\nCOMMIT\n"

    monkeypatch.setattr(module, "command", observed)
    monkeypatch.setattr(module.shutil, "which", lambda tool: "/usr/sbin/" + tool)
    monkeypatch.setattr(module, "forwarding_flags", lambda: {"ipv4": 0, "ipv6": {"all": 0}})
    for profile in (module.BASE_PROFILE, module.CROWDSEC_PROFILE):
        rows = module.inspect_network(native, profile)
        assert "PRAHO_NETWORK_COMPLETE" in rows
        projected = [json.loads(row.partition(" ")[2]) for row in rows if row.startswith("PRAHO_CROWDSEC_NFT ")]
        unowned = [json.loads(row.partition(" ")[2]) for row in rows if row.startswith("PRAHO_NETWORK_NATIVE ")]
        assert metadata not in projected + unowned
        assert foreign in unowned
        if profile == module.CROWDSEC_PROFILE:
            assert projected == owned_firewall()
            verify_owned_firewall(projected, PROTECTED)
        else:
            assert projected == []


@pytest.mark.parametrize("secondary", [False, True])
def test_ssh_extension_has_exact_forced_command_and_preserves_base_digest(secondary: bool) -> None:
    source = (ROOT / "deploy/ansible/roles/ssh-hardening/templates/sshd_config.j2").read_text()
    files = [".ssh/authorized_keys", ".ssh/authorized_keys2"] if secondary else [".ssh/authorized_keys"]
    variables = {"ssh_phase_ports": [9876], "ssh_authorized_keys_files": files, "ssh_webmin_tunnel_enabled": True}
    base = Environment(autoescape=True).from_string(source).render(**variables)
    assert inspector().canonical_ssh_digest(base) == SSH_CONFIG_DIGESTS[" ".join(files)]
    enabled = Environment(autoescape=True).from_string(source).render(**variables, ssh_crowdsec_gateway_enabled=True)
    assert "Match User praho-crowdsec\n" in enabled
    assert "    ForceCommand " + policy.GATEWAY_COMMAND + "\n" in enabled
    assert "    DisableForwarding yes\n" in enabled
    assert inspector().canonical_ssh_digest(enabled) == policy.CROWDSEC_SSH_CONFIG_DIGESTS[" ".join(files)]


def test_ssh_projection_only_adds_gateway_fields_for_selected_extension() -> None:
    module = inspector()
    source = "forcecommand sudo -n /usr/local/libexec/praho-crowdsec-gateway\ndisableforwarding yes\n"
    assert module._ssh_projection(source) == {"forcecommand": ["unreviewed"]}
    assert module._ssh_projection(source, profile=policy.CROWDSEC_PROFILE) == {
        "forcecommand": [policy.GATEWAY_COMMAND],
        "disableforwarding": ["yes"],
    }


def test_native_service_projection_rejects_extra_overrides_without_publishing_them() -> None:
    module = inspector()
    properties = {
        "FragmentPath": "/usr/lib/systemd/system/crowdsec.service",
        "DropInPaths": "/etc/systemd/system/crowdsec.service.d/praho.conf",
        "Environment": "LC_ALL=C LANG=C",
        "EnvironmentFiles": "",
        "Type": "notify",
        "ExecStart": "{ path=/usr/bin/crowdsec ; argv[]=/usr/bin/crowdsec -c /etc/crowdsec/config.yaml ; ignore_errors=no ; pid=1 ; }",
        "ExecStartPre": "{ path=/usr/bin/crowdsec ; argv[]=/usr/bin/crowdsec -c /etc/crowdsec/config.yaml -t -error ; ignore_errors=no ; pid=1 ; }",
        "FragmentSha256": "ec110a27de1ceaa991dd07bbe2cff69413b5c1f7bafd73870a98cb6a77e335ab",
    }
    assert module.canonical_crowdsec_service("crowdsec.service", properties)
    for key, value in (
        ("DropInPaths", properties["DropInPaths"] + " /etc/systemd/system/crowdsec.service.d/foreign.conf"),
        ("Environment", "PRIVATE_TOKEN=do-not-publish"),
        ("EnvironmentFiles", "/etc/private.env"),
        ("ExecStart", properties["ExecStart"].replace(" -c ", " -unexpected private-value -c ")),
    ):
        assert not module.canonical_crowdsec_service("crowdsec.service", {**properties, key: value})


def test_native_bouncer_accepts_exact_signed_etc_unit_and_owned_execution_override() -> None:
    module = inspector()
    executable = "/usr/local/libexec/praho-crowdsec-bouncer"
    configuration = "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    properties = {
        "FragmentPath": "/etc/systemd/system/crowdsec-firewall-bouncer.service",
        "FragmentSha256": "1c459fdc032edf948d2e97eae4ca1160c093f234898c1fb14dcf641fe9fb26f5",
        "DropInPaths": "/etc/systemd/system/crowdsec-firewall-bouncer.service.d/praho.conf",
        "Environment": "",
        "EnvironmentFiles": "",
        "Type": "notify",
        "ExecStart": "{ path="
        + executable
        + " ; argv[]="
        + executable
        + " -c "
        + configuration
        + " ; ignore_errors=no ; pid=1 ; }",
        "ExecStartPre": "{ path="
        + executable
        + " ; argv[]="
        + executable
        + " -c "
        + configuration
        + " -t ; ignore_errors=no ; pid=1 ; }",
    }
    assert module.canonical_crowdsec_service("crowdsec-firewall-bouncer.service", properties)
    assert not module.canonical_crowdsec_service(
        "crowdsec-firewall-bouncer.service", {**properties, "FragmentSha256": "f" * 64}
    )


def test_native_service_reader_accepts_omitted_empty_environment_files_and_rejects_duplicate_commands(
    monkeypatch,
) -> None:
    module = inspector()
    observed = {}
    contents = {}
    for unit, executable, configuration, suffix, environment, fragment in (
        (
            "crowdsec.service",
            "/usr/bin/crowdsec",
            "/etc/crowdsec/config.yaml",
            " -t -error",
            "LC_ALL=C LANG=C",
            "/usr/lib/systemd/system/crowdsec.service",
        ),
        (
            "crowdsec-firewall-bouncer.service",
            "/usr/local/libexec/praho-crowdsec-bouncer",
            "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml",
            " -t",
            "",
            "/etc/systemd/system/crowdsec-firewall-bouncer.service",
        ),
    ):
        contents[fragment] = unit.encode()
        fields = {
            "FragmentPath": fragment,
            "DropInPaths": "/etc/systemd/system/" + unit + ".d/praho.conf",
            "Type": "notify",
            "Environment": environment,
            "ExecStart": "{ path="
            + executable
            + " ; argv[]="
            + executable
            + " -c "
            + configuration
            + " ; ignore_errors=no ; pid=1 ; }",
            "ExecStartPre": "{ path="
            + executable
            + " ; argv[]="
            + executable
            + " -c "
            + configuration
            + suffix
            + " ; ignore_errors=no ; pid=1 ; }",
        }
        observed[unit] = "\n".join(name + "=" + value for name, value in fields.items())
    monkeypatch.setattr(
        module, "CROWDSEC_UNIT_SHA256", {unit: hashlib.sha256(unit.encode()).hexdigest() for unit in observed}
    )
    monkeypatch.setattr(module, "_root_file", lambda path: contents[str(path)])
    monkeypatch.setattr(module, "command", lambda argv: observed[argv[-1]])
    assert module._crowdsec_services_canonical()
    observed["crowdsec.service"] += (
        "\nExecStartPre={ path=/bin/false ; argv[]=/bin/false ; ignore_errors=no ; pid=1 ; }"
    )
    assert not module._crowdsec_services_canonical()


def test_exact_owned_schema_accepts_both_families_and_protected_membership() -> None:
    assert verify_owned_firewall(owned_firewall(), PROTECTED) is None


@pytest.mark.parametrize(
    "mutation",
    [
        "priority",
        "hook",
        "verdict",
        "order",
        "set_type",
        "missing",
        "duplicate",
        "foreign",
        "protect_all",
        "ban_members",
    ],
)
def test_owned_schema_refuses_each_independent_relaxation(mutation: str) -> None:
    entries = copy.deepcopy(owned_firewall())
    if mutation == "priority":
        entries[1]["chain"]["prio"] = 0
    elif mutation == "hook":
        entries[1]["chain"]["hook"] = "forward"
    elif mutation == "verdict":
        entries[5]["rule"]["expr"][-1] = {"accept": None}
    elif mutation == "order":
        entries[4], entries[5] = entries[5], entries[4]
    elif mutation == "set_type":
        entries[3]["set"]["type"] = "ipv6_addr"
    elif mutation == "missing":
        entries.pop()
    elif mutation == "duplicate":
        entries.append(copy.deepcopy(entries[5]))
    elif mutation == "foreign":
        entries.append({"flowtable": {"family": "inet", "table": "praho_crowdsec4", "name": "offload"}})
    elif mutation == "protect_all":
        entries[2]["set"]["elem"] = [{"prefix": {"addr": "0.0.0.0", "len": 0}}]
    else:
        entries[3]["set"]["elem"] = ["198.51.100.9"]
    with pytest.raises(ValidationError):
        verify_owned_firewall(entries, PROTECTED)


def test_inventory_protection_cannot_be_removed_or_silently_expanded() -> None:
    for wanted in (PROTECTED[:-1], [*PROTECTED, "198.51.100.0/24"]):
        with pytest.raises(ValidationError):
            verify_owned_firewall(owned_firewall(), wanted)


@pytest.fixture
def configuration_facts(monkeypatch: pytest.MonkeyPatch) -> tuple[list[str], str]:
    monkeypatch.setattr(policy, "EXPECTED_HELPER_SHA256", "a" * 64)
    monkeypatch.setattr(policy, "EXPECTED_ARTIFACT_LOCK_SHA256", "d" * 64, raising=False)
    monkeypatch.setattr(policy, "EXPECTED_BOUNCER_SHA256", {"arm64": "b" * 64}, raising=False)
    managed = dict.fromkeys(policy.MANAGED_FILES, "e" * 64)
    managed["/usr/local/libexec/praho-crowdsec-gateway"] = "a" * 64
    managed["/etc/sudoers.d/praho-crowdsec"] = hashlib.sha256(policy.GATEWAY_SUDO.encode()).hexdigest()
    managed["/etc/praho-crowdsec/artifacts.lock.json"] = "d" * 64
    native_policy = {
        "schema": 1,
        "host_kind": "node",
        "simulation": True,
        "protected_cidrs": PROTECTED,
        "artifact_lock_sha256": "d" * 64,
        "bouncer_binary_sha256": "b" * 64,
        "managed_files": managed,
    }
    digest = hashlib.sha256(json.dumps(native_policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    rows = [
        "PRAHO_CROWDSEC_CONFIG "
        + json.dumps(
            {
                "configuration_digest": digest,
                "configuration_sha256": "f" * 64,
                "installation_id": "f3e18796-206d-42c7-8ddd-d5044d2ac113",
                "root_owned": True,
            }
        ),
        "PRAHO_CROWDSEC_POLICY "
        + json.dumps({key: value for key, value in native_policy.items() if key != "managed_files"}),
        "PRAHO_CROWDSEC_RUNTIME "
        + json.dumps(
            {
                "architecture": "arm64",
                "engine_version": "1.8.2",
                "engine_active": True,
                "bouncer_active": False,
                "bouncer_binary_sha256": "b" * 64,
                "database_matches": True,
                "simulation_bans_empty": True,
                "configuration_canonical": True,
                "services_canonical": True,
            }
        ),
    ]
    rows += [
        "PRAHO_CROWDSEC_FILE " + json.dumps({"path": path, "sha256": value, "root_owned": True})
        for path, value in managed.items()
    ]
    return rows, digest


def test_configuration_binds_actual_owned_files_and_operator_intended_digest(
    configuration_facts: tuple[list[str], str],
) -> None:
    rows, digest = configuration_facts
    assert policy.verify_configuration(rows, digest, PROTECTED) == PROTECTED
    with pytest.raises(ValidationError):
        policy.verify_configuration(rows, "9" * 64, PROTECTED)


def test_unknown_architecture_and_missing_bouncer_hash_cannot_form_a_valid_policy(configuration_facts) -> None:
    rows, _ = configuration_facts
    values = {
        name: json.loads(next(row.partition(" ")[2] for row in rows if row.startswith("PRAHO_CROWDSEC_" + name + " ")))
        for name in ("CONFIG", "POLICY", "RUNTIME")
    }
    values["POLICY"]["bouncer_binary_sha256"] = None
    values["RUNTIME"].update(architecture="mips", bouncer_binary_sha256=None)
    managed = {
        json.loads(row.partition(" ")[2])["path"]: json.loads(row.partition(" ")[2])["sha256"]
        for row in rows
        if row.startswith("PRAHO_CROWDSEC_FILE ")
    }
    digest = hashlib.sha256(
        json.dumps({**values["POLICY"], "managed_files": managed}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    values["CONFIG"]["configuration_digest"] = digest
    changed = [row for row in rows if row.startswith("PRAHO_CROWDSEC_FILE ")]
    changed += ["PRAHO_CROWDSEC_" + name + " " + json.dumps(value) for name, value in values.items()]
    with pytest.raises(ValidationError):
        policy.verify_configuration(changed, digest, PROTECTED)


@pytest.mark.parametrize(
    "tag,key,value",
    [
        ("CONFIG", "root_owned", False),
        ("CONFIG", "installation_id", "invalid"),
        ("RUNTIME", "engine_active", False),
        ("RUNTIME", "bouncer_active", True),
        ("RUNTIME", "database_matches", False),
        ("RUNTIME", "simulation_bans_empty", False),
        ("RUNTIME", "configuration_canonical", False),
        ("RUNTIME", "services_canonical", False),
        ("RUNTIME", "bouncer_binary_sha256", "9" * 64),
        ("FILE", "root_owned", False),
        ("FILE", "sha256", "9" * 64),
        ("FILE", "path", "/unreviewed/root-file"),
        ("POLICY", "protected_cidrs", []),
        ("POLICY", "artifact_lock_sha256", "9" * 64),
    ],
)
def test_each_configuration_change_withdraws_qualification(
    configuration_facts: tuple[list[str], str],
    tag: str,
    key: str,
    value: object,
) -> None:
    rows, digest = configuration_facts
    prefix = "PRAHO_CROWDSEC_" + tag + " "
    index = next(index for index, row in enumerate(rows) if row.startswith(prefix))
    observed = json.loads(rows[index].removeprefix(prefix))
    observed[key] = value
    rows[index] = prefix + json.dumps(observed)
    with pytest.raises(ValidationError):
        policy.verify_configuration(rows, digest, PROTECTED)


@pytest.fixture
def qualified_node(configuration_facts: tuple[list[str], str]):
    path = ROOT / "services/platform/tests/provisioning/test_node_security_policy.py"
    spec = importlib.util.spec_from_file_location("crowdsec_base_policy_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    evidence = module.node_policy_evidence()
    services = evidence["services"]
    for index, row in enumerate(services):
        tag, _, raw = row.partition(" ")
        if tag in {"PRAHO_SSH_GLOBAL", "PRAHO_SSH_ROOT", "PRAHO_SSH_TUNNEL"}:
            projection = json.loads(raw)
            projection["disableforwarding"] = ["no"]
            services[index] = tag + " " + json.dumps(projection)
        elif tag == "PRAHO_SSH_CONFIG":
            services[index] = (
                tag
                + " "
                + json.dumps(
                    {"sha256": policy.CROWDSEC_SSH_CONFIG_DIGESTS[".ssh/authorized_keys .ssh/authorized_keys2"]}
                )
            )
    global_projection = json.loads(
        next(row.partition(" ")[2] for row in services if row.startswith("PRAHO_SSH_GLOBAL "))
    )
    gateway = {
        **global_projection,
        "forcecommand": [policy.GATEWAY_COMMAND],
        "permittty": ["no"],
        "disableforwarding": ["yes"],
    }
    services += [
        "PRAHO_SSH_GATEWAY " + json.dumps(gateway),
        "PRAHO_SSH_GATEWAY_ACCOUNT "
        + json.dumps(
            {
                "present": True,
                "name": "praho-crowdsec",
                "uid": 998,
                "gid": 998,
                "home": "/home/praho-crowdsec",
                "shell": "/bin/sh",
            }
        ),
        'PRAHO_SSH_GATEWAY_KEYS {"status":"complete","files":[".ssh/authorized_keys",".ssh/authorized_keys2"]}',
        "PRAHO_SSH_GATEWAY_KEY " + json.dumps({"fingerprint": module.OPERATOR_FINGERPRINT, "options": ["restrict"]}),
        *configuration_facts[0],
    ]
    evidence["listeners"].append("tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*")
    for family, table in policy.TABLES.items():
        evidence["firewall"].append("NFT input chain: " + family + ":" + table + ":input")
    evidence["firewall"] += ["PRAHO_CROWDSEC_NFT " + json.dumps(entry) for entry in owned_firewall()]
    return evidence, configuration_facts[1], module.OPERATOR_FINGERPRINT


def qualify(evidence, digest: str, fingerprint: str) -> None:
    verify_evidence(
        evidence,
        "praho-api",
        PROTECTED,
        expected_operator_fingerprints=[fingerprint],
        policy_version=policy.CROWDSEC_PROFILE,
        expected_configuration_digest=digest,
        expected_gateway_fingerprint=fingerprint,
    )


def test_selected_extension_accepts_full_owned_evidence_and_base_profile_refuses_it(qualified_node) -> None:
    evidence, digest, fingerprint = qualified_node
    qualify(evidence, digest, fingerprint)
    with pytest.raises(ValidationError):
        verify_evidence(evidence, "praho-api", PROTECTED, expected_operator_fingerprints=[fingerprint])


@pytest.mark.parametrize(
    "mutation",
    [
        "public_lapi",
        "missing_lapi",
        "command",
        "forwarding",
        "key",
        "key_options",
        "configuration",
        "missing_owned_set",
    ],
)
def test_extension_does_not_relax_existing_auth_or_inventory_controls(qualified_node, mutation: str) -> None:
    evidence, digest, fingerprint = qualified_node
    if mutation == "public_lapi":
        evidence["listeners"][-1] = "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*"
    elif mutation == "missing_lapi":
        evidence["listeners"].pop()
    elif mutation in {"command", "forwarding", "key", "key_options"}:
        tag = "PRAHO_SSH_GATEWAY" if mutation in {"command", "forwarding"} else "PRAHO_SSH_GATEWAY_KEY"
        index = next(index for index, row in enumerate(evidence["services"]) if row.startswith(tag + " "))
        row = json.loads(evidence["services"][index].partition(" ")[2])
        field, value = {
            "command": ("forcecommand", ["none"]),
            "forwarding": ("disableforwarding", ["no"]),
            "key": ("fingerprint", "SHA256:" + "A" * 43),
            "key_options": ("options", ["restrict", "port-forwarding"]),
        }[mutation]
        row[field] = value
        evidence["services"][index] = tag + " " + json.dumps(row)
    elif mutation == "configuration":
        digest = "9" * 64
    else:
        evidence["firewall"].pop()
    with pytest.raises(ValidationError):
        qualify(evidence, digest, fingerprint)
