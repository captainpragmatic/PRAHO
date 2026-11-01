"""Web-only restore dispatch must not recreate excluded native features."""

import io
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from django.core.exceptions import ValidationError

from apps.provisioning.virtualmin_backup_service import RestoreConfig, restore_domain_params
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_restore_policy import (
    inspect_web_archive,
    prepare_restore_params,
    restore_destination_refusal,
    validate_source_rollback,
)
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.provisioning.virtualmin_tasks import run_virtualmin_restore
from apps.provisioning.virtualmin_validators import WEB_ONLY_VIRTUALMIN_FEATURES
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class RestoreFeatureSelectionTests(TestCase):
    def test_default_restore_selects_only_web_features_and_limits_domain_recreation(self):
        params = restore_domain_params(domain="site.example.test", source="/private/backup.tar.gz")
        self.assertNotIn("all-features", params)
        self.assertEqual(params["feature"], list(WEB_ONLY_VIRTUALMIN_FEATURES))
        self.assertEqual(params["only-features"], "")


class NativeArchiveInspectionTests(TestCase):
    domain = "site.example.test"

    def archive(self, *, fields=None, members=(), metadata=True):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "backup.tar.gz"
        content = {"dom": self.domain, **dict.fromkeys(WEB_ONLY_VIRTUALMIN_FEATURES, "1"), **(fields or {})}
        with tarfile.open(path, "w:gz") as bundle:
            rows = list(members)
            if metadata:
                rows.append(
                    (
                        f"./{self.domain}_virtualmin",
                        "\n".join(f"{key}={value}" for key, value in content.items()).encode(),
                    )
                )
            for name, data in rows:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                bundle.addfile(member, io.BytesIO(data))
        return path

    def test_current_manifest_and_native_metadata_must_agree(self):
        path = self.archive()
        self.assertEqual(
            inspect_web_archive(path, self.domain, list(WEB_ONLY_VIRTUALMIN_FEATURES)), WEB_ONLY_VIRTUALMIN_FEATURES
        )
        with self.assertRaises(ValidationError):
            inspect_web_archive(path, self.domain, ["unix", "dir", "web"])

    def test_missing_manifest_feature_list_requires_actual_native_inspection(self):
        self.assertEqual(inspect_web_archive(self.archive(), self.domain), WEB_ONLY_VIRTUALMIN_FEATURES)
        with self.assertRaises(ValidationError):
            inspect_web_archive(self.archive(metadata=False), self.domain)

    def test_mixed_features_and_hidden_ancillary_members_are_refused(self):
        for feature in ("mail", "dns", "webmin", "ftp", "postgres", "unknown-plugin"):
            with self.subTest(feature=feature), self.assertRaises(ValidationError):
                inspect_web_archive(
                    self.archive(members=[(f"./{self.domain}_{feature}.tar", b"data")]),
                    self.domain,
                    list(WEB_ONLY_VIRTUALMIN_FEATURES),
                )
        for feature in ("mail", "dns", "webmin", "virtualmin-awstats"):
            with self.subTest(native_flag=feature), self.assertRaises(ValidationError):
                inspect_web_archive(self.archive(fields={feature: "1"}), self.domain)

    def test_domain_identity_layout_and_duplicate_metadata_are_preserved(self):
        for name in ("../outside", "/absolute", "other.example.test_dir.tar", ".backup/../../outside"):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                inspect_web_archive(self.archive(members=[(name, b"data")]), self.domain)
        with self.assertRaises(ValidationError):
            inspect_web_archive(self.archive(fields={"dom": "other.example.test"}), self.domain)
        with self.assertRaises(ValidationError):
            inspect_web_archive(self.archive(members=[(f"./{self.domain}_virtualmin", b"duplicate")]), self.domain)

    def test_subdirectory_payload_is_not_extracted_or_confused_with_native_metadata(self):
        with self.assertRaises(ValidationError):
            inspect_web_archive(
                self.archive(members=[(f"{self.domain}_dir/etc/passwd", b"do not extract")]), self.domain
            )

    def prepare(self, archive, *, restore_configuration=False):
        server = VirtualminServer(security_state="verified_web")
        account = VirtualminAccount(domain=self.domain)
        with (
            patch("apps.provisioning.virtualmin_restore_policy.VirtualminServer.objects.get", return_value=server),
            patch("apps.provisioning.virtualmin_restore_policy.restore_destination_refusal", return_value=None),
        ):
            return prepare_restore_params(
                account,
                server,
                archive,
                {},
                source="/private/backup.tar.gz",
                force=True,
                restore_configuration=restore_configuration,
            )

    def test_ordinary_restore_selects_core_configuration_before_web_components(self):
        params = self.prepare(self.archive(), restore_configuration=True)
        self.assertEqual(params["feature"], ["virtualmin", *WEB_ONLY_VIRTUALMIN_FEATURES])
        self.assertEqual(params["only-features"], "")
        self.assertNotIn("all-features", params)

    def test_migration_default_keeps_its_existing_component_and_credential_scope(self):
        params = self.prepare(self.archive())
        self.assertEqual(params["feature"], list(WEB_ONLY_VIRTUALMIN_FEATURES))

    def test_native_empty_script_marker_is_admitted_without_ancillary_payloads(self):
        path = self.archive(members=[(f"{self.domain}_virtualmin_scripts", b"")])
        self.assertIn("virtualmin", self.prepare(path, restore_configuration=True)["feature"])

    def test_configuration_restore_refuses_meaningful_ancillary_bookkeeping(self):
        for suffix in ("admins", "users", "scripts", "initial", "saved_aliases", "unclassified"):
            with self.subTest(suffix=suffix), self.assertRaises(ValidationError):
                self.prepare(
                    self.archive(members=[(f"{self.domain}_virtualmin_{suffix}", b"meaningful records")]),
                    restore_configuration=True,
                )

    def test_configuration_opt_in_does_not_admit_ancillary_services(self):
        with self.assertRaises(ValidationError):
            self.prepare(self.archive(fields={"mail": "1"}), restore_configuration=True)

    def test_migration_does_not_activate_or_reinterpret_ancillary_metadata(self):
        path = self.archive(members=[(f"{self.domain}_virtualmin_admins", b"not restored by web callbacks")])
        self.assertEqual(self.prepare(path)["feature"], list(WEB_ONLY_VIRTUALMIN_FEATURES))

    def default_plan(self):
        limits = (
            "aliasdomslimit",
            "aliaslimit",
            "bwlimit",
            "capabilities",
            "dbslimit",
            "domslimit",
            "featurelimits",
            "forceunder",
            "ipfollow",
            "mailboxlimit",
            "migrate",
            "nodbname",
            "norename",
            "quota",
            "realdomslimit",
            "safeunder",
            "uquota",
        )
        return (
            "id=0\nname=Default Plan\nfile=/etc/webmin/virtual-server/plans/0\n"
            + "".join(f"{name}=\n" for name in limits)
        ).encode()

    def test_only_the_qualified_default_plan_can_accompany_configuration(self):
        plan = self.default_plan()
        path = self.archive(fields={"plan": "0"}, members=[(f"{self.domain}_virtualmin_plan", plan)])
        self.assertIn("virtualmin", self.prepare(path, restore_configuration=True)["feature"])
        for unsafe in (
            plan.replace(b"id=0", b"id=99"),
            plan.replace(b"capabilities=\n", b"capabilities=webmin\n"),
            plan.replace(b"featurelimits=\n", b"featurelimits=mail\n"),
            plan + b"unclassified=value\n",
            plan + b"id=0\n",
        ):
            with self.subTest(plan_shape=unsafe.splitlines()[-1]), self.assertRaises(ValidationError):
                self.prepare(
                    self.archive(fields={"plan": "0"}, members=[(f"{self.domain}_virtualmin_plan", unsafe)]),
                    restore_configuration=True,
                )
        with self.assertRaises(ValidationError):
            self.prepare(
                self.archive(fields={"plan": "99"}, members=[(f"{self.domain}_virtualmin_plan", plan)]),
                restore_configuration=True,
            )


class SourceRollbackAdmissionTests(VirtualminTaskTestBase):
    def setUp(self):
        super().setUp()
        self.server.security_state = "acknowledged_source_only"
        self.server.save(update_fields=["security_state"])
        self.metadata = {
            "domain": self.account.domain,
            "praho_service_id": str(self.account.service_id),
            "node_id": str(self.server.pk),
            "virtualmin_domain_id": "1234567890",
        }

    def validate(self, metadata=None, domain_id="1234567890", force=True):
        validate_source_rollback(
            self.account,
            self.server,
            self.metadata if metadata is None else metadata,
            live_domain_id=domain_id,
            force=force,
        )

    def test_original_existing_domain_can_be_restored_only_with_explicit_force(self):
        self.assertIsNone(restore_destination_refusal(self.account, self.server, force=True))
        self.validate()
        self.assertIsNotNone(restore_destination_refusal(self.account, self.server, force=False))
        with self.assertRaises(ValidationError):
            self.validate(force=False)

    def test_source_exception_does_not_allow_recreation_or_other_backup_identity(self):
        for field in self.metadata:
            with self.subTest(field=field), self.assertRaises(ValidationError):
                self.validate({**self.metadata, field: "other"})
        with self.assertRaises(ValidationError):
            self.validate(domain_id="")

    def test_website_repoint_revokes_original_source_rollback_authority(self):
        replacement = VirtualminServer.objects.create(hostname="replacement.example.test")
        VirtualminAccount.objects.filter(pk=self.account.pk).update(server=replacement)
        with self.assertRaises(ValidationError):
            self.validate()
        self.assertIsNotNone(restore_destination_refusal(self.account, self.server, force=True))

    def test_force_does_not_admit_an_unreviewed_new_node(self):
        VirtualminServer.objects.filter(pk=self.server.pk).update(
            security_state="unreviewed", legacy_security_admission=False
        )
        self.assertIsNotNone(restore_destination_refusal(self.account, self.server, force=True))

    def test_unqualified_restore_is_refused_before_queue_and_chain_mutation(self):
        VirtualminServer.objects.filter(pk=self.server.pk).update(
            security_state="unreviewed", legacy_security_admission=False
        )
        with patch("django_q.tasks.async_task") as enqueue:
            result = VirtualminBackupManagementService(self.server).create_restore_job(
                self.account, RestoreConfig(backup_id="backup", force_restore=True)
            )
        self.assertTrue(result.is_err())
        enqueue.assert_not_called()
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_worker_rechecks_ordinary_and_pair_restores_before_reading_or_mutating(self):
        VirtualminServer.objects.filter(pk=self.server.pk).update(
            security_state="unreviewed", legacy_security_admission=False
        )
        for mode in ("ordinary", "pair"):
            with self.subTest(mode=mode):
                job = VirtualminProvisioningJob.objects.create(
                    operation="restore_domain",
                    account=self.account,
                    server=self.server,
                    parameters={
                        "backup_id": "backup",
                        "base_backup_id": "base",
                        "differential_backup_id": "diff",
                        "restore_mode": mode,
                        "force_restore": True,
                        "task_budget_seconds": 600,
                    },
                )
                with patch(
                    "apps.provisioning.virtualmin_backup_service.VirtualminBackupService._download_backup_to_spool"
                ) as download:
                    run_virtualmin_restore(str(job.pk))
                job.refresh_from_db()
                self.assertEqual(job.status, "failed")
                download.assert_not_called()
