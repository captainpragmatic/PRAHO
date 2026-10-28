"""Invariants the hosted-mail contracts rely on (docs/architecture/account-hostnames-mail-contracts.md)."""

import ast
import base64
import importlib.util
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.test import SimpleTestCase, TestCase

from apps.provisioning.virtualmin_mail_dns import (
    MailDnsRecord,
    MailDnsSnapshot,
    build_mail_dns_plan,
    mail_dns_snapshot_digest,
)
from apps.provisioning.virtualmin_mail_publisher import MailDnsPublisher, mail_dns_publisher
from apps.provisioning.virtualmin_mail_service import MailDkimObservation
from apps.provisioning.virtualmin_mailbox_service import MailboxCreate, MailboxPassword
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_tasks import _RETRYABLE_OPERATIONS
from apps.provisioning.virtualmin_views import _job_can_be_retried
from tests.provisioning.test_account_hostname_models import _make_server

APPS = Path(settings.BASE_DIR) / "apps"
NATIVE = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files"
DOMAIN = "mail-contract.example.test"
ACCOUNT_NAME = "mail5678.accounts.example.test"
SPF_INCLUDE = "_spf.accounts.example.test"


def _python_sources() -> list[Path]:
    return sorted(path for path in APPS.rglob("*.py") if "migrations" not in path.parts)


def _string_constants(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    return {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}


class MailRecordSlotVocabularyTests(SimpleTestCase):
    """The publisher binds record changes by slot name, so the planner's consent must use exactly these names."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        encoded = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.dkim = MailDkimObservation(
            "praho", f"praho._domainkey.{DOMAIN}", "v=DKIM1; k=rsa; p=" + base64.b64encode(encoded).decode()
        )

    def plan(self, *records):
        digest = mail_dns_snapshot_digest(DOMAIN, 3, tuple(records), scope="zone", covered_rrsets=())
        snapshot = MailDnsSnapshot(DOMAIN, 3, digest, tuple(records))
        return build_mail_dns_plan(
            snapshot, domain=DOMAIN, account_hostname=ACCOUNT_NAME, spf_include=SPF_INCLUDE, dkim=self.dkim
        ).unwrap()

    def test_consent_changes_use_only_the_three_mail_slots(self):
        consent = self.plan().to_consent()
        self.assertEqual({change["slot"] for change in consent["changes"]}, {"dkim", "spf", "mx"})
        mx = next(change for change in consent["changes"] if change["slot"] == "mx")
        self.assertEqual([row["rdata"] for row in mx["after"]], [f"10 {ACCOUNT_NAME}."])

    def test_a_slot_already_in_its_desired_state_is_omitted_from_the_sparse_changes(self):
        current_mx = MailDnsRecord(DOMAIN, "MX", 300, f"10 {ACCOUNT_NAME}.")
        consent = self.plan(current_mx).to_consent()
        self.assertEqual({change["slot"] for change in consent["changes"]}, {"dkim", "spf"})


class MailboxChangeSinglePathTests(SimpleTestCase):
    """Mailbox and alias changes reach the node only through the hosted-mail change path."""

    VIRTUALMIN_USER_PROGRAMS = frozenset({"create-user", "modify-user", "delete-user", "create-alias", "delete-alias"})

    def test_no_platform_module_calls_virtualmin_user_or_alias_programs_directly(self):
        allowed = APPS / "provisioning/virtualmin_validators.py"
        offenders = [
            str(path.relative_to(APPS))
            for path in _python_sources()
            if path != allowed and _string_constants(path) & self.VIRTUALMIN_USER_PROGRAMS
        ]
        self.assertEqual(offenders, [])

    def test_the_native_change_action_has_one_platform_owner(self):
        wrapper_owners = {
            APPS / "provisioning/virtualmin_mail_domain_service.py",
            APPS / "provisioning/virtualmin_mailbox_service.py",
        }
        action_owners = {
            APPS / "provisioning/virtualmin_mail_domain_service.py",
            APPS / "provisioning/virtualmin_mail_service.py",
        }
        wrapper = re.compile(r"\bapply_native_mail_change\b")
        wrapper_offenders = [
            str(path.relative_to(APPS))
            for path in _python_sources()
            if path not in wrapper_owners and wrapper.search(path.read_text())
        ]
        action_offenders = [
            str(path.relative_to(APPS))
            for path in _python_sources()
            if path not in action_owners and "apply_mail_change" in _string_constants(path)
        ]
        self.assertEqual((wrapper_offenders, action_offenders), ([], []))


class MailNodeJobGenericRetryTests(TestCase):
    """Node mail jobs close only through their own staff action, never the generic job retry."""

    def test_staff_generic_retry_never_offers_a_failed_node_mail_job(self):
        job = VirtualminProvisioningJob.objects.create(
            correlation_id="mail-node-contract",
            operation="configure_mail_node",
            server=_make_server(),
            account=None,
            status="failed",
            retry_count=0,
            max_retries=3,
        )
        self.assertNotIn("configure_mail_node", _RETRYABLE_OPERATIONS)
        self.assertFalse(_job_can_be_retried(job))


class NativeMailBundleBoundaryTests(SimpleTestCase):
    def test_only_read_only_observations_share_the_node_lock(self):
        specification = importlib.util.spec_from_file_location("mail_contract_native", NATIVE / "praho-mail.py")
        assert specification is not None and specification.loader is not None
        native = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(native)
        self.assertEqual(native.SHARED_ACTIONS, frozenset({"inspect_node", "inspect_domain"}))

    def test_domain_action_entry_scripts_stay_outside_the_installed_bundle(self):
        tree = ast.parse((NATIVE / "praho_mail_setup.py").read_text())
        native_files = next(
            ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "NATIVE_FILES" for target in node.targets)
        )
        self.assertIn("praho-mail.py", native_files)
        self.assertFalse({"praho-mail-domain.py", "praho-mail-domain.pl"} & set(native_files))


class MailContractSeamTests(SimpleTestCase):
    def test_the_enrollment_publisher_satisfies_the_publication_protocol(self):
        self.assertIsInstance(mail_dns_publisher(), MailDnsPublisher)

    def test_mailbox_passwords_never_appear_in_a_change_representation(self):
        for change in (MailboxCreate("info", "S3cret-pass-1"), MailboxPassword("info", "S3cret-pass-1")):
            with self.subTest(kind=type(change).__name__):
                self.assertNotIn("S3cret-pass-1", repr(change))
