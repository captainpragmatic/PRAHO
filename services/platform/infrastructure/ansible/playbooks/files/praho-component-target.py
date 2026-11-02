#!/usr/bin/env python3
"""Own a fresh disabled native target before selected data or credentials can be exposed."""

from __future__ import annotations

import base64
import grp
import hashlib
import importlib.util
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

POLICY = "component-target-v1"
MAX_CREATION_VALUE = 4096
MAX_POLICY_RECEIPT_BYTES = 4096
SHADOW_COLUMNS = 9
FEATURES = frozenset({"unix", "dir", "web", "ssl", "mysql", "logrotate"})


def _module(filename: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Native component target support is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


journals = _module("praho-component-journal.py", "component_target_receipts")
preflight = _module("praho-component-target-preflight.py", "component_target_namespace")
archives = _module("praho-component-target-archive.py", "component_target_archives")
usage_writers = _module("praho-component-usage.py", "component_target_usage")


def native(program: str, arguments: list[str]) -> str:
    result = subprocess.run(  # noqa: S603 -- fixed native callback wrapper; sensitive arguments only on private stdin
        ["/usr/bin/perl", str(Path(__file__).with_name("praho-component-native-command.pl"))],
        input=json.dumps({"program": program, "arguments": arguments}),
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    if result.returncode:
        raise ValueError("Native component target callback did not complete; inspect the private operation receipt")
    return result.stdout.strip()


class TargetCoordinator:
    def __init__(  # noqa: PLR0913 -- approved source scope, target connection and exact native creation/archive identity
        self,
        manifest: dict[str, Any],
        operation_id: str,
        target_identity: str,
        archive_sha256: str,
        creation_params: dict[str, str],
        *,
        archive: Path | None = None,
        state_dir: Path | None = None,
        boot_id: str | None = None,
    ) -> None:
        self.manifest = json.loads(json.dumps(manifest, allow_nan=False))
        self.creation = dict(creation_params)
        self.operation, self.checksum, self.target_identity = operation_id, archive_sha256, target_identity
        self.domain, self.owner = manifest["source"]["domain"], manifest["source"]["owner"]
        self.archive = archive or Path("/var/lib/praho-transfer") / ("migration_" + operation_id + ".tar.gz")
        self._parameters()
        if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (target_identity, archive_sha256)):
            raise ValueError("Exact target connection and selected archive digests are required")
        authority = archives.source.authority_digest(self.manifest)
        digest = hashlib.sha256(
            json.dumps(
                [POLICY, authority, target_identity, archive_sha256, self.creation],
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        self.journal = journals.ComponentJournal(
            state_dir or Path("/var/lib/praho/component-targets") / operation_id,
            manifest["source"]["domain_id"],
            {
                "operation_id": operation_id,
                "scope_digest": digest,
                "boot_id": boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            },
        )

    def _parameters(self) -> None:
        required = {"domain", "user", "template", "desc", *FEATURES}
        if (
            not required <= self.creation.keys()
            or self.creation.keys() - required - {"quota", "bandwidth"}
            or self.creation["domain"] != self.domain
            or self.creation["user"] != self.owner
            or self.creation["template"] != "Default Settings"
            or any(self.creation[name] != "" for name in FEATURES)
            or any(
                not isinstance(value, str) or len(value) > MAX_CREATION_VALUE or any(char in value for char in "\0\r\n")
                for value in self.creation.values()
            )
            or any(not self.creation[name].isdecimal() for name in ("quota", "bandwidth") if name in self.creation)
        ):
            raise ValueError(
                "Review a qualified default target template, exact owner and explicit website-only creation scope"
            )

    def _state(self) -> dict[str, Any]:
        state = self.journal.read()
        if state is None:
            raise ValueError("The target has no durable component ownership receipt")
        self.journal.assert_owned(state)
        if state.get("policy") != POLICY or state.get("phase") not in {
            "creating",
            "created",
            "prepared",
            "restoring",
            "held",
            "sealed",
            "activating",
            "active",
            "policy_changing",
            "removing",
            "removed",
        }:
            raise ValueError("The native component target receipt is unrecognized")
        return state

    def _domain(self, state: dict[str, Any], *, held: bool) -> dict[str, str]:
        domain_id = state.get("target_domain_id")
        if not isinstance(domain_id, str) or re.fullmatch(r"[0-9]{1,30}", domain_id) is None:
            raise ValueError("The native target domain has no confirmed ownership identity")
        fields = archives.source.inspection._fields(Path("/etc/webmin/virtual-server/domains") / domain_id)
        owner = pwd.getpwnam(self.owner)
        if (
            fields.get("id") != domain_id
            or fields.get("dom") != self.domain
            or fields.get("user") != self.owner
            or fields.get("home") != self.manifest["source"]["home"]
            or int(fields.get("uid", "0")) != state["target_uid"]
            or int(fields.get("gid", "0")) != state["target_gid"]
            or state["target_uid"] <= 0
            or state["target_gid"] <= 0
            or owner.pw_uid != state["target_uid"]
            or owner.pw_gid != state["target_gid"]
            or owner.pw_dir != self.manifest["source"]["home"]
            or fields.get("parent")
            or fields.get("alias")
            or any(fields.get(name) != "1" for name in ("unix", "dir", "web"))
            or any(fields.get(name) == "1" for name in archives.archives.OTHER_FEATURES)
            or (held and "unix" not in fields.get("disabled", "").split(","))
        ):
            raise ValueError("The target native domain, owner, features or held state changed")
        return fields

    def prepare(self) -> dict[str, Any]:
        """A lost create response parks, rather than adopting a same-named native domain or SQL login."""
        with self.journal.locked():
            self._assert_preparable()
            archives.read_component_archive(self.archive, self.checksum, self.operation, self.manifest)
            state = self.journal.read()
            if state is None:
                _versions, preparation = archives.source.inspection._callbacks()
                if preparation or self.manifest["preparation"]:
                    raise ValueError("Native target callbacks or source components require qualification")
                absence = preflight.preflight_target(self.manifest)
                if self.domain in native("list-domains", ["--name-only"]).splitlines():
                    raise ValueError("The native target domain already exists; never adopt it")
                state = self.journal.create({"policy": POLICY, "phase": "creating", "absence": absence})
                values = {**self.creation, "pass": "Qz9" + secrets.token_hex(32)}
                arguments = []
                for name, value in values.items():
                    arguments.append("--" + name)
                    if value:
                        arguments.append(value)
                native("create-domain", arguments)
                identity = native("list-domains", ["--domain", self.domain, "--id-only"])
                if re.fullmatch(r"[0-9]{1,30}", identity) is None:
                    raise ValueError("The created native target did not return one exact domain identity")
                fields = archives.source.inspection._fields(Path("/etc/webmin/virtual-server/domains") / identity)
                state.update(
                    phase="created",
                    target_domain_id=identity,
                    target_uid=int(fields["uid"]),
                    target_gid=int(fields["gid"]),
                )
                if self.manifest["databases"]:
                    state["native_sql_owner_hosts"] = self._native_sql_hosts()
                self._domain(state, held=False)
                self.journal.write(state)
            state = self._state()
            if state["phase"] == "creating":
                raise ValueError("Native target creation is unresolved; inspect its exact identity before retrying")
            if state["phase"] not in {"created", "prepared"}:
                raise ValueError("A restoring or held target cannot replay native creation/suspension")
            self._domain(state, held=state["phase"] == "prepared")
            if state["phase"] == "created":
                native("disable-domain", ["--domain", self.domain])
                self._domain(state, held=True)
            shadow = archives.source.inspection._command(["/usr/bin/getent", "shadow", self.owner])
            if not shadow.split(":")[1].startswith(("!", "*")):
                raise ValueError("The new target Unix login is not independently held")
            self._prepare_frontend_policy()
            state["phase"] = "prepared"
            self.journal.write(state)
            return {"operation_id": self.operation, "target_domain_id": state["target_domain_id"], "phase": "prepared"}

    @staticmethod
    def _prepare_frontend_policy() -> None:
        # A restore can remove an old mail/admin ServerAlias, so its previously
        # held spelling reaches the neutral default. Explicitly inherit the
        # global pair-maintenance rules there BEFORE any native restore.
        bindings = archives.source.inspection.defaults.apache.ApacheBindings()
        default = Path("/etc/apache2/conf-enabled/praho-default-site.conf").resolve(strict=True)
        if default.parent not in {Path("/etc/apache2/conf-enabled"), Path("/etc/apache2/conf-available")} or (
            b"ServerName praho-default.invalid" not in bindings.read(default, 0o644)
        ):
            raise ValueError("The qualified target has no protected neutral default frontend")
        bindings.install()
        with bindings.transaction():
            if bindings.refresh():
                bindings.reload()

    def _native_sql_hosts(self) -> list[str]:
        hosts = preflight.mysql.native_sql(
            f"SELECT Host FROM mysql.user WHERE User = '{self.owner}' ORDER BY Host"  # noqa: S608 -- exact validated owner
        )
        if not hosts or any(len(row) != 1 or preflight.mysql.HOST.fullmatch(row[0]) is None for row in hosts):
            raise ValueError("The fresh native target owner has no complete SQL host identity")
        return [row[0] for row in hosts]

    def _identity(self, state: dict[str, Any]) -> dict[str, str]:
        return {"domain": self.domain, "owner": self.owner, "domain_id": state["target_domain_id"]}

    @staticmethod
    def _recovery() -> Any:
        # The same pure owner-aging schema used by Platform is shipped as a
        # protected sibling; no Django installation is needed on the node.
        directory = str(Path(__file__).parent)
        if directory not in sys.path:
            sys.path.insert(0, directory)
        recovery = _module("praho-recovery.py", "component_target_owner_recovery")
        recovery.CREDENTIAL_HELPER = Path(__file__).with_name("praho-recovery-credentials.pl")
        return recovery

    def _pair(self, action: str, state: dict[str, Any]) -> None:
        if action not in {"restore", "release"}:
            raise ValueError("An exact target restore-hold action is required")
        environment = {
            **os.environ,
            "PRAHO_PAIR_ACTION": action,
            "PRAHO_DOMAIN": self.domain,
            "PRAHO_DOMAIN_ID": state["target_domain_id"],
            "PRAHO_CHAIN_TOKEN": self.operation,
            "PRAHO_STAGING_DIR": str(self.archive.parent),
            "PRAHO_BASE_ARCHIVE": self.archive.name,
            "PRAHO_BASE_SHA": self.checksum,
            "PRAHO_DIFF_ARCHIVE": "",
            "PRAHO_DIFF_SHA": "",
            "PRAHO_RECOVERY": "1",
            "PRAHO_WEB_ONLY": "1",
            "PRAHO_LOCK_WAIT": "60",
            "PRAHO_STEP_HOLD": "0",
            "PRAHO_RUN_DIR": "/run/praho",
            "PRAHO_PAIR_STATE_DIR": "/var/lib/praho/pair-restore",
            "PRAHO_HELD_STATE_DIR": str(self.journal.directory),
            "PRAHO_APACHE_DIR": "/etc/apache2/conf-enabled",
            "PRAHO_HTTP_PORT": "80",
            "PRAHO_HTTPS_PORT": "443",
            "PRAHO_RECOVERY_SSL_HELPER": str(Path(__file__).with_name("praho-recovery-ssl.py")),
            "PRAHO_APACHE_BINDINGS_HELPER": str(Path(__file__).with_name("praho-apache-bindings.py")),
        }
        result = subprocess.run(  # noqa: S603 -- fixed existing restore runner and exact operation-bound environment
            ["/bin/bash", str(Path(__file__).with_name("praho-pair-restore.sh"))],
            env=environment,
            capture_output=True,
            text=True,
            timeout=3600,
            check=False,
        )
        matches = re.findall(r"PAIR_RESULT=([A-Za-z0-9+/=]+)", result.stdout)
        if result.returncode or len(matches) != 1:
            raise ValueError("The native target restore hold is uncertain; preserve its private receipt")
        receipt = json.loads(base64.b64decode(matches[0], validate=True))
        if (
            receipt.get("token") != self.operation
            or receipt.get("domain_id") != state["target_domain_id"]
            or receipt.get("action") != action
            or receipt.get("outcome") != ("ok" if action == "restore" else "released")
        ):
            raise ValueError(
                "The native target restore hold did not independently verify: "
                + str(receipt.get("outcome", "missing outcome"))
                + ": "
                + str(receipt.get("reason", ""))[:500]
            )

    def _held(self, state: dict[str, Any], private: dict[str, Any]) -> dict[str, Any]:
        self._domain(state, held=True)
        self._web(state).verify()
        self._recovery().verify_held(self._identity(state))
        if self.manifest["databases"]:
            self._sql(state, private).verify()
        archives.files.repair_component_files(
            Path(self.manifest["source"]["home"]), private, state["target_uid"], state["target_gid"]
        )
        receipt = {"operation_id": self.operation, "target_domain_id": state["target_domain_id"], "phase": "held"}
        digest = hashlib.sha256(
            json.dumps(
                [POLICY, receipt, self.target_identity, self.checksum, self.journal.identity["scope_digest"]],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        return {**receipt, "target_receipt_sha256": digest}

    def _sql(self, state: dict[str, Any], private: dict[str, Any]) -> Any:
        sql = _module("praho-component-target-database.py", "component_target_application_sql")
        return sql.TargetDatabase(
            self.manifest,
            private["principals"],
            tuple(state["native_sql_owner_hosts"]),
            state["target_domain_id"],
            self.operation,
            self.journal.identity["scope_digest"],
            state_dir=self.journal.directory / "sql",
        )

    def _web(self, state: dict[str, Any]) -> Any:
        web = _module("praho-component-web-fence.py", "component_target_ingress")
        return web.WebIngressFence(
            state["target_domain_id"],
            self.operation,
            self.domain,
            tuple(self.manifest["routing"]["website_names"]),
            state["web_sha256"],
        )

    def restore(self) -> dict[str, Any]:
        with self.journal.locked():
            state = self._state()
            private = archives.read_component_archive(self.archive, self.checksum, self.operation, self.manifest)
            if state["phase"] == "held":
                return self._held(state, private)
            if state["phase"] != "prepared":
                raise ValueError("Native target restoration is unprepared or interrupted; inspect before replaying")
            with usage_writers.UsageWriterGuard() as usage:
                self._domain(state, held=True)
                state["phase"] = "restoring"
                self.journal.write(state)
                recovery = self._recovery()
                recovery.stage_cron(
                    self.archive,
                    self.checksum,
                    self.journal.directory / (self.operation + ".cron"),
                    self.journal.directory / (self.operation + ".json"),
                    self._identity(state),
                )
                self._pair("restore", state)
                # Native restore replaces the vhost from an unmanaged source.
                # Finish the qualified telemetry repair before sealing its bytes;
                # the periodic writer uses this same lock and then has no edit.
                usage.reconcile()
                site = Path("/etc/apache2/sites-available") / (self.domain + ".conf")
                state["web_sha256"] = hashlib.sha256(archives.source.inspection._read(site).encode()).hexdigest()
                self.journal.write(state)
                self._web(state).apply()
                if self.manifest["databases"]:
                    self._sql(state, private).apply()
                receipt = self._held(state, private)
                state.update(phase="held", held_receipt_sha256=receipt["target_receipt_sha256"])
                self.journal.write(state)
                return receipt

    def verify(self) -> dict[str, Any]:
        with self.journal.locked():
            state = self._state()
            if state["phase"] != "held":
                raise ValueError("The selected native target is not fully restored and held")
            private = archives.read_component_archive(self.archive, self.checksum, self.operation, self.manifest)
            _versions, preparation = archives.source.inspection._callbacks()
            if preparation:
                raise ValueError("The native target callbacks changed after qualification")
            return self._held(state, private)

    def _activation_payload(self, private: dict[str, Any]) -> dict[str, Any]:
        recovery = self._recovery()
        metadata = self.journal.directory / (self.operation + ".json")
        recovery.checked(metadata)
        payload = json.loads(metadata.read_text())
        owner_hashes = {row["authentication_string"] for row in private["principals"] if row["user"] == self.owner}
        if len(owner_hashes) > 1:
            raise ValueError("Prepare one native owner SQL credential across its selected host accounts")
        # A native owner with a separate SQL credential must never fall back to
        # the retained source Unix/mail plaintext password. Keep only the
        # independently hash-qualified application password needed by the
        # native MariaDB billing callback; hash-only enable is unqualified.
        if owner_hashes:
            native_hash = next(iter(owner_hashes))
            password = payload["native_credentials"].get("mysql_pass", "")
            if (
                not password
                or preflight.mysql.native_owner_password(
                    {"user": self.owner, "mysql_pass": password}, self.manifest["databases"]
                )
                != password
            ):
                raise ValueError("The selected native SQL owner has no qualified billing recovery credential")
            credentials = {
                "pass": "",
                "mysql_pass": password,
                "mysql_enc_pass": native_hash,
                "disabled_oldmysql": native_hash,
            }
        else:
            credentials = {
                "pass": "",
                "mysql_pass": "Qz9" + secrets.token_hex(32),
                "mysql_enc_pass": "",
                "disabled_oldmysql": "",
            }
        return {**payload, "native_credentials": credentials, "enabled": True}

    def _verify_owner(self, payload: dict[str, Any], *, enabled: bool) -> None:
        shadow = archives.source.inspection._command(["/usr/bin/getent", "shadow", self.owner]).strip().split(":")
        aging = payload["owner_shadow"]
        expected_aging = [aging[key] for key in ("change", "min", "max", "warn", "inactive", "expire", "flag")]
        if len(shadow) != SHADOW_COLUMNS or shadow[2:] != expected_aging:
            raise ValueError("Native target Unix login aging changed during activation")
        if (enabled and shadow[1] != payload["credential_hash"]) or (
            not enabled and not shadow[1].startswith(("!", "*"))
        ):
            raise ValueError("Native target Unix credential or suspension state changed during activation")

    def _activate_native(self, state: dict[str, Any], private: dict[str, Any], *, enabled: bool) -> None:
        recovery = self._recovery()
        payload = self._activation_payload(private)
        # This callback stages the original Unix hash/aging while Unix remains
        # disabled. Keep the actual crontab empty through native enable_mysql;
        # only the explicit final selected-cron write can start jobs.
        recovery.run(["perl", str(recovery.CREDENTIAL_HELPER)], content=json.dumps(payload).encode())
        recovery.run(["crontab", "-u", self.owner, "-"], content=b"")
        recovery.verify_held(self._identity(state))
        if enabled:
            native("enable-domain", ["--domain", self.domain])
        self._domain(state, held=not enabled)
        if self.manifest["databases"]:
            self._sql(state, private).activate(enabled=enabled)
        self._verify_owner(payload, enabled=enabled)
        cron_path = self.journal.directory / (self.operation + ".cron")
        recovery.checked(cron_path)
        cron = cron_path.read_bytes()
        if payload["sha256"] != hashlib.sha256(cron).hexdigest():
            raise ValueError("The selected target schedule changed after restoration")
        selected_cron = cron if enabled else recovery.suspended_cron(cron)
        recovery.run(["crontab", "-u", self.owner, "-"], content=selected_cron)
        if recovery.run(["crontab", "-u", self.owner, "-l"]) != selected_cron:
            raise ValueError("The selected target schedule did not independently activate")
        state["activation_web_sha256"] = hashlib.sha256(
            archives.source.inspection._read(Path("/etc/apache2/sites-available") / (self.domain + ".conf")).encode()
        ).hexdigest()
        self.journal.write(state)
        # Both guards remain owned until credentials, grants, original lock
        # states and the selected schedule have independently verified.
        self._web(state).release_after_native_change(state["activation_web_sha256"])
        self._pair("release", state)

    def _active(self, state: dict[str, Any], private: dict[str, Any]) -> dict[str, Any]:
        fields = self._domain(state, held=not state["enabled"])
        if bool(fields.get("disabled")) is state["enabled"]:
            raise ValueError("The active component target policy changed")
        if self.manifest["databases"]:
            self._sql(state, private).verify(active=True)
        return {"operation_id": self.operation, "target_domain_id": state["target_domain_id"], "phase": "active"}

    def seal(self, expected_receipt: str) -> dict[str, Any]:
        """Fence already-dispatched compensation before sealing the source or moving ownership."""
        with self.journal.locked():
            state = self._state()
            if expected_receipt != state.get("held_receipt_sha256"):
                raise ValueError("The target seal requires its exact independently verified held receipt")
            if state["phase"] not in {"held", "sealed"}:
                raise ValueError("Target seal is unprepared or interrupted; preserve its exact native receipts")
            private = archives.read_component_archive(self.archive, self.checksum, self.operation, self.manifest)
            if self._held(state, private)["target_receipt_sha256"] != expected_receipt:
                raise ValueError("The held target seal receipt changed")
            state["phase"] = "sealed"
            self.journal.write(state)
            return {
                "operation_id": self.operation,
                "target_domain_id": state["target_domain_id"],
                "phase": "sealed",
                "target_receipt_sha256": expected_receipt,
            }

    def activate(self, expected_receipt: str, *, enabled: bool) -> dict[str, Any]:
        """Only the leased forward worker may invoke this after the source seal and database cutover commit."""
        with self.journal.locked():
            state = self._state()
            if type(enabled) is not bool or expected_receipt != state.get("held_receipt_sha256"):
                raise ValueError("Component activation requires its exact independently verified held receipt")
            private = archives.read_component_archive(self.archive, self.checksum, self.operation, self.manifest)
            if state["phase"] == "active":
                if state.get("enabled") is not enabled:
                    raise ValueError("Completed component activation policy changed")
                return self._active(state, private)
            if state["phase"] != "sealed":
                raise ValueError("Component activation requires a sealed target and no interrupted native work")
            if self._held(state, private)["target_receipt_sha256"] != expected_receipt:
                raise ValueError("The held component activation receipt changed")
            state.update(phase="activating", enabled=enabled)
            self.journal.write(state)
            self._activate_native(state, private, enabled=enabled)
            receipt = self._active(state, private)
            state["phase"] = "active"
            self.journal.write(state)
            return receipt

    def _policy_native(self, state: dict[str, Any], *, enabled: bool) -> None:
        result = subprocess.run(  # noqa: S603 -- fixed protected policy callback, exact identity on bounded stdin
            ["/usr/bin/perl", str(Path(__file__).with_name("praho-component-policy.pl"))],
            input=json.dumps(
                {
                    **self._identity(state),
                    "uid": str(state["target_uid"]),
                    "gid": str(state["target_gid"]),
                    "enabled": enabled,
                }
            ),
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        if (
            result.returncode
            or len(result.stdout) > MAX_POLICY_RECEIPT_BYTES
            or json.loads(result.stdout) != {"enabled": enabled, "domain_id": state["target_domain_id"]}
        ):
            raise ValueError("Current native component policy is uncertain; preserve its exact identity")

    def reconcile_policy(self, *, enabled: bool) -> dict[str, Any]:
        """Apply current native policy without replaying archived credentials or schedules."""
        with self.journal.locked():
            state = self._state()
            if type(enabled) is not bool or state["phase"] not in {"active", "policy_changing"}:
                raise ValueError("Current policy requires a completed owned component activation")
            if state["phase"] == "policy_changing" and state.get("policy_enabled") is not enabled:
                raise ValueError("Reconcile the uncertain native policy before accepting another decision")
            fields = self._domain(state, held=False)
            private = archives.read_component_archive(self.archive, self.checksum, self.operation, self.manifest)
            state.update(phase="policy_changing", policy_enabled=enabled)
            self.journal.write(state)
            if bool(fields.get("disabled")) is enabled:
                self._policy_native(state, enabled=enabled)
            if self.manifest["databases"]:
                self._sql(state, private).reconcile_policy(enabled=enabled)
            state["enabled"] = enabled
            receipt = self._active(state, private)
            state["phase"] = "active"
            self.journal.write(state)
            return receipt

    def _private_archive(self, expected: dict[str, Any] | None = None) -> dict[str, Any] | None:
        if (
            self.archive.name != "migration_" + self.operation + ".tar.gz"
            or self.archive.parent.resolve() != self.archive.parent
        ):
            raise ValueError("The target archive is outside its exact operation namespace")
        parent = self.archive.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise ValueError("The target archive directory is not private owned storage")
        try:
            descriptor = os.open(self.archive, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
                or hashlib.file_digest(stream, "sha256").hexdigest() != self.checksum
            ):
                raise ValueError("The private target archive changed before retirement")
            identity = {"device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size}
        if expected is not None and identity != expected:
            raise ValueError("The private target archive identity was reused")
        return identity

    def _unprepared_artifact_journal(self) -> Any:
        return journals.ComponentJournal(
            self.journal.directory / "unprepared-artifacts", self.manifest["source"]["domain_id"], self.journal.identity
        )

    def _assert_preparable(self) -> None:
        if self._unprepared_artifact_journal().read() is not None:
            raise ValueError("Terminal unprepared artifact retirement sealed this target operation")

    def retire_unprepared_archive(self) -> dict[str, Any]:
        """Forget only exact terminal UUID staging before any native target preparation."""
        with self.journal.locked():
            if self.journal.read() is not None:
                raise ValueError("Unprepared archive cleanup cannot adopt a native target preparation receipt")
            journal = self._unprepared_artifact_journal()
            with journal.locked():
                state = journal.read()
                receipt = {"operation_id": self.operation, "phase": "artifacts_retired"}
                if state is not None:
                    journal.assert_owned(state)
                    if state.get("policy") != "component-unprepared-artifacts-v1" or state.get("phase") not in {
                        "retiring",
                        "retired",
                    }:
                        raise ValueError("The unprepared artifact retirement receipt is unrecognized")
                    if state["phase"] == "retired":
                        if self.archive.exists() or self.archive.is_symlink():
                            raise ValueError("The retired unprepared archive namespace was reused")
                        return receipt
                    raise ValueError("Unprepared archive retirement was interrupted; inspect the exact private receipt")
                identity = self._private_archive()
                if identity is not None:
                    identity["ctime_ns"] = self.archive.lstat().st_ctime_ns
                state = journal.create(
                    {"policy": "component-unprepared-artifacts-v1", "phase": "retiring", "archive_identity": identity}
                )
                if identity is not None:
                    current = self._private_archive(
                        {key: value for key, value in identity.items() if key != "ctime_ns"}
                    )
                    if current is None or self.archive.lstat().st_ctime_ns != identity["ctime_ns"]:
                        raise ValueError("The exact unprepared archive identity was reused before retirement")
                    self.archive.unlink()
                    descriptor = os.open(self.archive.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                state["phase"] = "retired"
                journal.write(state)
                return receipt

    def retire_artifacts(self) -> dict[str, Any]:
        """A terminal controller decision may forget only UUID-owned private staging."""
        with self.journal.locked():
            state = self._state()
            if state["phase"] not in {"active", "removed"}:
                raise ValueError("Private staging cannot retire an unfinished native component operation")
            receipt = {
                "operation_id": self.operation,
                "target_domain_id": state["target_domain_id"],
                "phase": "artifacts_retired",
            }
            if state.get("artifacts_phase") == "retired":
                if any(
                    path.exists() or path.is_symlink()
                    for path in (
                        self.archive,
                        self.journal.directory / (self.operation + ".json"),
                        self.journal.directory / (self.operation + ".cron"),
                    )
                ):
                    raise ValueError("A retired private artifact namespace was reused")
                return receipt
            if state.get("artifacts_phase") not in {None, "retiring"}:
                raise ValueError("Private target staging has an unrecognized retirement receipt")
            identity = self._private_archive(state.get("artifact_archive"))
            state.update(artifacts_phase="retiring", artifact_archive=identity)
            self.journal.write(state)
            self._recovery().cleanup_staged(
                self.journal.directory, self.archive.parent, self.operation, self._identity(state)
            )
            if identity is not None:
                if self._private_archive(identity) is None:
                    raise ValueError("The private target archive changed during retirement")
                self.archive.unlink()
            state["artifacts_phase"] = "retired"
            self.journal.write(state)
            return receipt

    def _assert_absent(self, state: dict[str, Any]) -> None:
        domain = Path("/etc/webmin/virtual-server/domains") / state["target_domain_id"]
        if (
            domain.exists()
            or domain.is_symlink()
            or self.domain in native("list-domains", ["--name-only"]).splitlines()
        ):
            raise ValueError("The exact native target domain is not independently absent")
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup(self.owner)
            except KeyError:
                continue
            raise ValueError("The owned native target Unix user or group still exists")

    def remove(self) -> dict[str, Any]:
        """Precommit compensation only; an active target can never be deleted through this action."""
        with self.journal.locked():
            state = self._state()
            receipt = {
                "operation_id": self.operation,
                "target_domain_id": state["target_domain_id"],
                "phase": "removed",
            }
            if state["phase"] == "removed":
                self._assert_absent(state)
                return receipt
            if state["phase"] not in {"prepared", "held"}:
                raise ValueError("Target compensation is unprepared, committed or interrupted; inspect before deletion")
            private = archives.read_component_archive(self.archive, self.checksum, self.operation, self.manifest)
            self._domain(state, held=True)
            restored = state["phase"] == "held"
            if restored:
                self._held(state, private)
            state["phase"] = "removing"
            self.journal.write(state)
            if restored:
                # Acquire the pair runner's lock and release its hold only while
                # the independent component guard still proves effective503.
                self._pair("release", state)
                self._web(state).verify()
            native("delete-domain", ["--domain", self.domain])
            self._assert_absent(state)
            if restored:
                if self.manifest["databases"]:
                    self._sql(state, private).retire()
                self._web(state).retire_after_domain_absence()
                self._recovery().cleanup_staged(
                    self.journal.directory, self.archive.parent, self.operation, self._identity(state)
                )
            state["phase"] = "removed"
            self.journal.write(state)
            return receipt
