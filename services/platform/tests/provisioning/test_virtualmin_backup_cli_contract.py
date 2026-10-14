"""Backup and restore requests must parse as valid Virtualmin command lines.

remote.cgi turns every query parameter into a command-line argument: an empty
value becomes a bare ``--flag``; any other value becomes ``--flag value``, and a
repeated parameter repeats the pair. ``backup-domain.pl`` and
``restore-domain.pl`` then reject any token they do not know with
"Unknown parameter ...". So ``all-features=True`` reaches the script as
``--all-features True`` and fails. That rejection was observed against
Virtualmin 8.3.0 in the lab (see docs/domain/virtualmin-incremental-contract.md).

The flag tables below are transcribed from the argument parsers of
webmin-virtual-server 8.3.0-1-gpl.
"""

from __future__ import annotations

from typing import cast
from unittest.mock import patch
from urllib.parse import urlencode

import requests
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import override_settings

from apps.common.types import Err, Ok
from apps.provisioning.virtualmin_backup_service import BackupConfig, RestoreConfig, VirtualminBackupService
from apps.provisioning.virtualmin_validators import VirtualminValidator
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase

_BACKUP_VALUED = frozenset(
    {"dest", "feature", "domain", "user", "reseller", "plan", "except-feature", "strftime", "option", "virtualmin",
     "except-virtualmin", "differential-of", "incremental-of", "purge", "key", "exclude", "include", "compression"}
)  # fmt: skip
_BACKUP_BARE = frozenset(
    {"parent", "all-features", "all-domains", "test", "ignore-errors", "separate", "mkdir", "onebyone",
     "newformat", "mailfiles", "as-owner", "all-virtualmin", "incremental", "differential", "no-incremental",
     "no-differential", "purge-debug", "no-sign", "sign", "multiline", "kill-running", "wait-running"}
)  # fmt: skip
_RESTORE_VALUED = frozenset(
    {"source", "feature", "domain", "except-feature", "option", "mysql-stop-time", "virtualmin", "only-features",
     "ip", "ip6", "key", "reuser"}
)  # fmt: skip
_RESTORE_BARE = frozenset(
    {"all-features", "all-domains", "test", "reuid", "no-reuid", "no-reuser", "fix", "mailfiles",
     "mysql-replay-binlogs", "as-owner", "all-virtualmin", "only-missing", "only-existing", "delete-existing",
     "default-ip", "shared-ip", "allocate-ip", "original-ip", "no-ip", "default-ip6", "shared-ip6", "allocate-ip6",
     "original-ip6", "no-ip6", "skip-warnings", "continue-on-error", "replication", "multiline"}
)  # fmt: skip
_FORMAT_KEYS = frozenset({"program", "json", "xml", "perl"})


def remote_cgi_argv(params: dict[str, object]) -> list[str]:
    """Rebuild the argv remote.cgi hands to the program for these query params."""
    pairs = urlencode(params, doseq=True).split("&")
    argv: list[str] = []
    for pair in pairs:
        raw_key, _, raw_value = pair.partition("=")
        key = requests.utils.unquote(raw_key.replace("+", " "))
        value = requests.utils.unquote(raw_value.replace("+", " "))
        if key in _FORMAT_KEYS:
            continue
        argv.append(f"--{key}")
        if value != "":
            argv.extend(value.split("\n"))
    return argv


def parse_like_virtualmin(argv: list[str], valued: frozenset[str], bare: frozenset[str]) -> list[str]:
    """Return the tokens Virtualmin would reject as 'Unknown parameter'."""
    unknown: list[str] = []
    tokens = list(argv)
    while tokens:
        token = tokens.pop(0)
        name = token.removeprefix("--")
        if token.startswith("--") and name in valued and tokens:
            tokens.pop(0)
        elif not (token.startswith("--") and name in bare):
            unknown.append(token)
    return unknown


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class BackupCommandLineContractTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.backups = VirtualminBackupService(self.server)

    def _dispatch(self, config: BackupConfig) -> dict[str, object]:
        sent: list[dict[str, object]] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            sent.append(cast("dict[str, object]", kwargs["params"]))
            return http_response({"status": "success"})

        metadata = self.backups._initialize_backup_metadata(self.account, config.backup_type, "cli-id", config)
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            result = self.backups._execute_backup_by_type(config, self.account, "cli-id", metadata)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(len(sent), 1)
        return sent[0]

    def test_full_backup_parses_without_unknown_parameters(self) -> None:
        for config in (
            BackupConfig(),
            BackupConfig(include_email=False),
            BackupConfig(include_email=False, include_databases=False, include_files=False, include_ssl=False),
        ):
            with self.subTest(config=config):
                argv = remote_cgi_argv(self._dispatch(config))
                self.assertEqual(parse_like_virtualmin(argv, _BACKUP_VALUED, _BACKUP_BARE), [])
                self.assertIn("--all-features", argv)
                # One archive file at dest: --newformat demands a directory.
                self.assertNotIn("--newformat", argv)

    def test_excluded_components_become_repeated_except_feature_after_all_features(self) -> None:
        argv = remote_cgi_argv(self._dispatch(BackupConfig(include_email=False, include_ssl=False)))

        all_features_at = argv.index("--all-features")
        excluded = [argv[i + 1] for i, token in enumerate(argv) if token == "--except-feature"]
        self.assertEqual(excluded, ["mail", "ssl"])
        # --except-feature filters the list --all-features built, so order matters.
        self.assertLess(all_features_at, argv.index("--except-feature"))

    def test_config_only_backup_selects_virtualmin_and_dir_features(self) -> None:
        argv = remote_cgi_argv(self._dispatch(BackupConfig(backup_type="config_only")))

        self.assertEqual(parse_like_virtualmin(argv, _BACKUP_VALUED, _BACKUP_BARE), [])
        selected = [argv[i + 1] for i, token in enumerate(argv) if token == "--feature"]
        self.assertEqual(selected, ["virtualmin", "dir"])
        self.assertNotIn("--all-features", argv)

    def test_restore_parses_without_unknown_parameters(self) -> None:
        sent: list[dict[str, object]] = []

        def capture(gateway: object, program: str, params: dict[str, object], timeout: int) -> object:
            sent.append(params)
            return Err("stop after capture")

        spool_path = "/nonexistent/spool/virtualmin_backup_" + "a" * 32 + ".tar.gz"
        metadata = {
            "archive_name": "virtualmin_backup_" + "a" * 32 + ".tar.gz",
            "checksum_sha256": "0" * 64,
            "praho_service_id": str(self.account.service_id),
            "domain": self.account.domain,
        }
        with (
            patch.object(self.backups, "_download_backup_to_spool", return_value=Ok((spool_path, metadata))),
            patch.object(self.backups, "_target_domain_gate", return_value=Ok(False)),
            patch.object(self.backups, "_push_archive_to_target", return_value=Ok(None)),
            patch.object(self.backups, "_cleanup_remote_archive"),
            patch.object(self.backups, "_call_checked", side_effect=capture),
        ):
            self.backups.restore_domain(self.account, RestoreConfig(backup_id="cli-restore"))

        self.assertEqual(len(sent), 1)
        argv = remote_cgi_argv(sent[0])
        self.assertEqual(parse_like_virtualmin(argv, _RESTORE_VALUED, _RESTORE_BARE), [])
        self.assertIn("--all-features", argv)


class RemoteCgiEmulationSelfTests(VirtualminTaskTestBase):
    """The emulation must reject what Virtualmin 8.3.0 rejected in the lab."""

    def test_boolean_values_and_unknown_flags_are_rejected(self) -> None:
        argv = remote_cgi_argv({"domain": "a.test", "dest": "/tmp/x", "all-features": True, "newformat": True})  # noqa: S108
        self.assertEqual(parse_like_virtualmin(argv, _BACKUP_VALUED, _BACKUP_BARE), ["True", "True"])
        argv = remote_cgi_argv({"domain": "a.test", "dest": "/tmp/x", "only-features": "virtualmin,dir"})  # noqa: S108
        self.assertEqual(
            parse_like_virtualmin(argv, _BACKUP_VALUED, _BACKUP_BARE), ["--only-features", "virtualmin,dir"]
        )


class RepeatedParameterValidationTests(VirtualminTaskTestBase):
    """A list parameter gets the same per-value checks as a single string."""

    def test_each_list_element_is_screened(self) -> None:
        self.assertEqual(
            VirtualminValidator.validate_virtualmin_params({"feature": ("virtualmin", "dir")}),
            {"feature": ["virtualmin", "dir"]},
        )
        for bad in (["dir", "<script>alert(1)</script>"], ["dir", 1], ["x" * 100_000]):
            with self.subTest(value=str(bad)[:40]), self.assertRaises(ValidationError):
                VirtualminValidator.validate_virtualmin_params({"feature": bad})
