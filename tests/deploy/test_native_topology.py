"""Controller topology validation happens before any host is changed."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from deploy.scripts import native_env


def git(*arguments: str) -> str:
    return subprocess.run([shutil.which("git") or "/usr/bin/git", *arguments],  # noqa: S603 -- fixture-owned repositories
                          capture_output=True, text=True, check=True).stdout.strip()


def configuration() -> dict[str, str]:
    return {
        "PRAHO_PLATFORM_SERVER": "192.0.2.10",
        "PRAHO_PORTAL_SERVER": "192.0.2.20",
        "PRAHO_PLATFORM_PUBLIC_IPV4": "192.0.2.11",
        "PRAHO_PORTAL_PUBLIC_IPV4": "192.0.2.21",
        "PRAHO_PORTAL_API_SOURCE_CIDRS": "192.0.2.22/32 2001:db8:2::/64",
        "PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS": "192.0.2.12/32",
        "PLATFORM_DOMAIN": "staff.example.test",
        "PORTAL_DOMAIN": "portal.example.test",
        "PRAHO_SSH_ALLOWED_CIDRS": "198.51.100.10/32",
        "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": "/operator/known_hosts",
        "PRAHO_SSH_PUBLIC_KEYS_FILE": "/operator/keys.pub",
    }


def test_platform_management_and_service_share_native_static_and_media_defaults() -> None:
    values = configuration() | {"DJANGO_SECRET_KEY": "platform", "PORTAL_DJANGO_SECRET_KEY": "portal"}
    platform, portal = native_env.runtime_environments(values, "prod", "split")
    assert platform["STATIC_ROOT"] == "/opt/praho/static"
    assert platform["MEDIA_ROOT"] == "/opt/praho/media"
    assert "MEDIA_ROOT" not in portal
    platform, _ = native_env.runtime_environments(values | {"MEDIA_ROOT": "/opt/praho/customer-uploads"}, "prod", "split")
    assert platform["MEDIA_ROOT"] == "/opt/praho/customer-uploads"


@pytest.mark.parametrize("path", ["/", "/opt/../etc", "/opt/has space", "/opt/root\nExecStart=/bin/false"])
@pytest.mark.parametrize("name", ["STATIC_ROOT", "MEDIA_ROOT"])
def test_native_runtime_paths_are_safe_for_units_and_edge_configuration(name: str, path: str) -> None:
    values = configuration() | {"DJANGO_SECRET_KEY": "platform", "PORTAL_DJANGO_SECRET_KEY": "portal", name: path}
    with pytest.raises(ValueError, match=name):
        native_env.runtime_environments(values, "prod", "split")


def test_production_defaults_to_split_and_inventory_is_connection_only() -> None:
    values = configuration() | {"DB_PASSWORD": "must-stay-on-controller"}
    topology = native_env.normalize_topology(values, "prod")
    inventory = topology.inventory()
    groups = inventory["all"]["children"]
    assert topology.mode == "split"
    assert groups["praho_platform"]["hosts"] == {"platform": {}}
    assert groups["praho_portal"]["hosts"] == {"portal": {}}
    hosts = groups["praho"]["hosts"]
    assert hosts["platform"]["ansible_host"] == "192.0.2.10"
    assert hosts["portal"]["ansible_host"] == "192.0.2.20"
    assert "StrictHostKeyChecking=yes" in hosts["portal"]["ansible_ssh_common_args"]
    assert "must-stay-on-controller" not in json.dumps(inventory)


@pytest.mark.parametrize("family,address", [(4, "224.0.0.1"), (6, "ff02::1"), (4, "169.254.1.1"), (6, "fe80::1")])
def test_public_ingress_rejects_multicast_and_link_local_addresses(family: int, address: str) -> None:
    with pytest.raises(ValueError, match="ingress"):
        native_env.normalize_topology(configuration() | {f"PRAHO_PLATFORM_PUBLIC_IPV{family}": address}, "prod")


@pytest.mark.parametrize("environment", ["dev", "staging", "prod"])
def test_combined_legacy_target_is_supported_when_selected(environment: str) -> None:
    values = configuration() | {"PRAHO_NATIVE_TOPOLOGY": "combined", "PRAHO_SERVER_IP": "192.0.2.10"}
    values.pop("PRAHO_PORTAL_SERVER")
    topology = native_env.normalize_topology(values, environment)
    assert topology.mode == "combined"
    assert topology.platform == topology.portal
    groups = topology.inventory()["all"]["children"]
    assert groups["praho_platform"]["hosts"] == groups["praho_portal"]["hosts"]


@pytest.mark.parametrize("environment", ["dev", "staging"])
def test_nonproduction_defaults_to_combined(environment: str) -> None:
    topology = native_env.normalize_topology({"PRAHO_SERVER_IP": "192.0.2.1"}, environment)
    assert topology.mode == "combined"


def test_conflicting_legacy_targets_fail_before_selecting_a_host() -> None:
    with pytest.raises(ValueError, match="legacy"):
        native_env.normalize_topology({"PRAHO_SERVER_IP": "192.0.2.1", "PRAHO_DEV_IP": "192.0.2.2"}, "dev")


@pytest.mark.parametrize(
    "change,match",
    [
        ({"PRAHO_PORTAL_SERVER": ""}, "PRAHO_PORTAL_SERVER"),
        ({"PRAHO_PORTAL_SERVER": "192.0.2.10"}, "distinct"),
        ({"PRAHO_NATIVE_TOPOLOGY": "typo"}, "PRAHO_NATIVE_TOPOLOGY"),
        ({"PRAHO_SERVER_IP": "192.0.2.99"}, "legacy"),
        ({"PRAHO_PORTAL_API_SOURCE_CIDRS": "0.0.0.0/0"}, "CIDRS"),
        ({"PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS": "::/0"}, "CIDRS"),
        ({"PRAHO_PORTAL_API_SOURCE_CIDRS": "0.0.0.0/1 128.0.0.0/1"}, "CIDRS"),
        ({"PRAHO_PLATFORM_PUBLIC_IPV4": "2001:db8::1"}, "IPV4"),
        ({"PRAHO_PORTAL_PUBLIC_IPV4": ""}, "public"),
        ({"PLATFORM_API_ALLOW_INSECURE_HTTP": "true"}, "HTTPS"),
        ({"PLATFORM_API_BASE_URL": "http://staff.example.test/api"}, "HTTPS"),
        ({"PORTAL_PAYMENT_WEBHOOK_URL": "http://portal.example.test/order/payment/webhook/"}, "HTTPS"),
        ({"PORTAL_TRUSTED_PROXY_CIDRS": "0.0.0.0/0"}, "local Caddy"),
    ],
)
def test_split_fails_closed(change: dict[str, str], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        native_env.normalize_topology(configuration() | change, "prod")


def test_ssh_pins_and_bootstrap_ports_are_per_host() -> None:
    values = configuration() | {
        "PRAHO_PLATFORM_SSH_PORT": "22",
        "PRAHO_PORTAL_SSH_PORT": "9876",
        "PRAHO_PORTAL_DEPLOY_KNOWN_HOSTS_FILE": "/operator/portal_known_hosts",
    }
    topology = native_env.normalize_topology(values, "prod")
    assert topology.platform.port == 22
    assert topology.portal.port == 9876
    assert topology.portal.known_hosts == "/operator/portal_known_hosts"


def test_paired_address_names_and_record_families_are_validated() -> None:
    values = configuration() | {"PRAHO_ADDRESS_IPV4_DOMAIN": "v4.example.test"}
    with pytest.raises(ValueError, match="paired"):
        native_env.normalize_topology(values, "prod")
    values["PRAHO_ADDRESS_IPV6_DOMAIN"] = "v6.example.test"
    values["PRAHO_PORTAL_PUBLIC_IPV6"] = "2001:db8::20"
    topology = native_env.normalize_topology(values, "prod")
    records = {"staff.example.test": {"192.0.2.11"}, "portal.example.test": {"192.0.2.21", "2001:db8::20"},
               "v4.example.test": {"192.0.2.21"}, "v6.example.test": {"2001:db8::20"}}
    topology.validate_dns(records.__getitem__)
    records["v4.example.test"].add("2001:db8::20")
    with pytest.raises(ValueError, match="DNS"):
        topology.validate_dns(records.__getitem__)


def test_release_is_resolved_to_a_full_commit_once(tmp_path: Path) -> None:
    sha = "a" * 40
    with patch("deploy.scripts.native_env.subprocess.run") as run:
        run.return_value.stdout = f"{sha}\trefs/heads/staging\n"
        run.return_value.returncode = 0
        assert native_env.resolve_release("https://example.test/repo.git", "staging") == sha
    assert run.call_count == 1
    assert run.call_args.args[0][-2:] == ["refs/heads/staging", "refs/tags/staging^{}"]


def test_missing_release_is_rejected() -> None:
    with patch("deploy.scripts.native_env.subprocess.run") as run:
        run.return_value.stdout = ""
        run.return_value.returncode = 0
        with pytest.raises(ValueError, match="release"):
            native_env.resolve_release("https://example.test/repo.git", "missing")


def test_a_full_sha_is_proven_to_be_an_available_commit_before_host_mutation(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    git("init", "-q", str(repository))
    git("-C", str(repository), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
        "commit", "--allow-empty", "-qm", "first release")
    sha = git("-C", str(repository), "rev-parse", "HEAD")
    native_env.validate_release(str(repository), sha)
    with pytest.raises(ValueError, match="commit"):
        native_env.validate_release(str(repository), "a" * 40)


def test_a_moving_branch_does_not_change_the_pinned_commit(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    git("init", "-q", "-b", "release", str(repository))
    commit = ["-C", str(repository), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "--allow-empty", "-qm"]
    git(*commit, "first")
    resolved = native_env.resolve_release(str(repository), "release")
    git(*commit, "second")
    moved = native_env.resolve_release(str(repository), "release")
    assert moved != resolved
    native_env.validate_release(str(repository), resolved)


def test_rsync_transport_uses_only_the_pinned_clean_release(tmp_path: Path) -> None:
    repository, checkout = tmp_path / "repository", tmp_path / "snapshot"
    git("init", "-q", str(repository))
    (repository / "release.txt").write_text("pinned source")
    git("-C", str(repository), "add", ".")
    git("-C", str(repository), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "release")
    sha = git("-C", str(repository), "rev-parse", "HEAD")
    (repository / "release.txt").write_text("uncommitted changes")
    (repository / ".env").write_text("private-controller-secret")
    native_env.materialize_release(str(repository), sha, checkout)
    assert (checkout / "release.txt").read_text() == "pinned source"
    assert not (checkout / ".env").exists()
    assert git("-C", str(checkout), "rev-parse", "HEAD") == sha
    assert not (checkout / ".git/FETCH_HEAD").exists()


def test_portal_configuration_is_filtered_before_transfer() -> None:
    values = configuration() | {
        "DJANGO_SECRET_KEY": "platform-session-key", "PORTAL_DJANGO_SECRET_KEY": "portal-session-key",
        "DB_PASSWORD": "database-only", "STRIPE_SECRET_KEY": "payment-only",
        "DJANGO_ENCRYPTION_KEY": "encryption-only", "HMAC_SECRET": "peer-authentication",
        "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": "callback-authentication",
    }
    platform, portal = native_env.runtime_environments(values, "prod", "split")
    assert platform["DB_PASSWORD"] == "database-only"
    assert platform["PORTAL_PAYMENT_WEBHOOK_URL"] == "https://portal.example.test/order/payment/webhook/"
    assert platform["INTERNAL_SERVICE_ALLOWED_DOMAINS"] == "portal.example.test"
    assert set(platform["ALLOWED_HOSTS"].split(",")) >= {"staff.example.test", "localhost", "127.0.0.1"}
    assert portal["PLATFORM_API_BASE_URL"] == "https://staff.example.test/api"
    assert portal["PLATFORM_API_ALLOW_INSECURE_HTTP"] == "false"
    assert portal["DJANGO_SECRET_KEY"] == "portal-session-key"
    assert portal["PLATFORM_API_SECRET"] == "peer-authentication"
    assert not {"DB_PASSWORD", "STRIPE_SECRET_KEY", "DJANGO_ENCRYPTION_KEY", "HMAC_SECRET"} & portal.keys()
    assert not any(secret in json.dumps(portal) for secret in ("database-only", "payment-only", "encryption-only"))


def test_platform_retains_native_runtime_configuration_while_portal_remains_filtered() -> None:
    values = configuration() | {"DJANGO_SECRET_KEY": "platform-key", "PORTAL_DJANGO_SECRET_KEY": "portal-key",
                                "PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE": "/etc/praho/operator_authorized_keys"}
    platform, portal = native_env.runtime_environments(values, "prod", "split")
    assert platform["PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE"] == values["PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE"]
    assert "PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE" not in portal


def test_combined_portal_connects_over_loopback() -> None:
    _, portal = native_env.runtime_environments(configuration() | {
        "PORTAL_DJANGO_SECRET_KEY": "portal-key", "DJANGO_SECRET_KEY": "platform-key", "HMAC_SECRET": "peer-key",
    }, "staging", "combined")
    assert portal["PLATFORM_API_BASE_URL"] == "http://127.0.0.1:8700/api"
    assert portal["PLATFORM_API_ALLOW_INSECURE_HTTP"] == "true"


def test_refuse_reused_application_identity() -> None:
    with pytest.raises(ValueError, match="distinct"):
        native_env.runtime_environments(configuration() | {
            "PORTAL_DJANGO_SECRET_KEY": "same", "DJANGO_SECRET_KEY": "same",
        }, "prod", "split")


@pytest.mark.parametrize("change", [{"PORTAL_HMAC_SECRET": ""}, {"PORTAL_HMAC_SECRET": "short"},
                                    {"PORTAL_HMAC_MODE": "legacy"}, {"PORTAL_HMAC_CREDENTIALS": "{}"},
                                    {"PORTAL_HMAC_CREDENTIALS": "not-json-private-value"}])
def test_invalid_peer_credentials_fail_on_controller_without_exposing_values(change: dict[str, str]) -> None:
    values = {"PLATFORM_DOMAIN": "staff.example.test", "PORTAL_DOMAIN": "portal.example.test",
              "DJANGO_SECRET_KEY": "platform", "PORTAL_DJANGO_SECRET_KEY": "portal", "DB_PASSWORD": "database",
              "HMAC_SECRET": "shared", "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": "callback", "PORTAL_ID": "portal-001",
              "PORTAL_HMAC_SECRET": "p" * 40, "PORTAL_HMAC_CREDENTIALS": json.dumps({"portal-001": "p" * 40})}
    with pytest.raises(ValueError, match="Portal HMAC") as error:
        native_env.validate_application_configuration(values | change, "staging")
    assert "not-json-private-value" not in str(error.value)


def test_failed_deploy_reasserts_holds_after_maintenance_was_established(tmp_path: Path) -> None:
    pins, keys = tmp_path / "pins", tmp_path / "keys"
    pins.write_text("fixture\n")
    keys.write_text("fixture\n")
    values = configuration() | {"PRAHO_NATIVE_TOPOLOGY": "split", "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": str(pins), "PRAHO_SSH_PUBLIC_KEYS_FILE": str(keys),
                                "DJANGO_SECRET_KEY": "platform", "PORTAL_DJANGO_SECRET_KEY": "portal",
                                "HMAC_SECRET": "hmac", "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": "callback", "DB_PASSWORD": "database",
                                "PORTAL_HMAC_SECRET": "p" * 40, "PORTAL_HMAC_CREDENTIALS": json.dumps({"portal-001": "p" * 40})}
    operations = []
    def run(command: list[str], **kwargs: object):
        import subprocess  # noqa: PLC0415
        parameters = json.loads(Path(command[-1][1:]).read_text())
        operations.append(command[command.index("-i") + 2])
        (Path(parameters["native_journal_directory"]) / "held-platform").touch()
        return subprocess.CompletedProcess(command, 1 if len(operations) == 1 else 0)
    with patch("deploy.scripts.native_env.validate_release"), patch("deploy.scripts.native_env.subprocess.run", side_effect=run), patch(
        "deploy.scripts.native_env.resolve_addresses", side_effect=lambda host: {
            "staff.example.test": {"192.0.2.11"}, "portal.example.test": {"192.0.2.21"},
            "192.0.2.10": {"192.0.2.10"}, "192.0.2.20": {"192.0.2.20"},
        }[host]
    ):
        assert native_env.run_native(values, tmp_path / "env", "staging", fetch_backup=None, version="a" * 40) == 1
    assert operations == ["playbooks/native.yml", "playbooks/native-hold.yml"]


@pytest.mark.parametrize("actions", [["delete"], ["delete", "create"], ["create", "delete"]])
def test_saved_adoption_plan_rejects_server_deletion_and_replacement(actions: list[str]) -> None:
    plan = {"format_version": "1.2", "prior_state": {"values": {"root_module": {"resources": [
        {"type": "hcloud_server", "address": "hcloud_server.platform", "values": {"id": "101"}},
        {"type": "hcloud_server", "address": "hcloud_server.portal[0]", "values": {"id": "102"}},
    ]}}}, "resource_changes": [{"type": "hcloud_server", "address": "hcloud_server.portal[0]", "change": {"actions": actions}}]}
    with pytest.raises(ValueError, match="delet"):
        native_env.validate_adoption_plan(plan, "split")


def test_saved_adoption_plan_retains_existing_servers_and_allows_new_firewall() -> None:
    plan = {"format_version": "1.2", "prior_state": {"values": {"root_module": {"resources": [
        {"type": "hcloud_server", "address": "hcloud_server.platform", "values": {"id": "101"}},
        {"type": "hcloud_server", "address": "hcloud_server.portal[0]", "values": {"id": "102"}},
    ]}}}, "resource_changes": [
        {"type": "hcloud_server", "address": "hcloud_server.portal[0]", "change": {"actions": ["update"]}},
        {"type": "hcloud_firewall", "address": "hcloud_firewall.portal[0]", "change": {"actions": ["create"]}},
    ]}
    native_env.validate_adoption_plan(plan, "split")


def test_empty_or_unbound_adoption_plan_is_not_proof() -> None:
    with pytest.raises(ValueError, match="prior"):
        native_env.validate_adoption_plan({"resource_changes": []}, "split")


@pytest.mark.parametrize("prior", [{"values": None}, {"values": {"root_module": []}},
                                  {"values": {"root_module": {"resources": [{"type": "hcloud_server", "values": None}]}}}])
def test_malformed_adoption_evidence_is_rejected_without_a_traceback(prior: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="prior"):
        native_env.validate_adoption_plan({"prior_state": prior, "resource_changes": []}, "split")
