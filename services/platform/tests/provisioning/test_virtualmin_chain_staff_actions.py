"""Staff and CLI actions that take a base or a differential backup, and the pair restore from the CLI.

The take actions create bases and differentials, so they follow the flag (provisioning.incremental_backups_enabled):
off, the account page does not offer them and a POST is refused. The pair restore only reads what already
exists, so it is offered and works whatever the flag says. There are no bulk differential actions.
"""

from __future__ import annotations

import re
from io import StringIO
from typing import Any
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.urls import reverse

from apps.common.types import Ok
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.settings.services import SettingsService
from apps.users.models import User
from tests.provisioning.test_virtualmin_account_exclusion import ExclusionCase
from tests.provisioning.test_virtualmin_chain_state import ChainFixtures

FLAG = "provisioning.incremental_backups_enabled"


class StaffActionCase(ChainFixtures, ExclusionCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.staff = User.objects.create_user(
            email="chain-staff@example.com", password="chain-staff-password", staff_role="admin"
        )
        self.client.force_login(self.staff)
        self.detail = reverse("provisioning:virtualmin_account_detail", args=[self.account.pk])
        self.base_url = reverse("provisioning:virtualmin_account_take_base", args=[self.account.pk])
        self.differential_url = reverse("provisioning:virtualmin_account_take_differential", args=[self.account.pk])
        listing = patch.object(VirtualminBackupService, "list_backups", return_value=Ok([]))
        listing.start()
        self.addCleanup(listing.stop)

    def set_flag(self, value: bool) -> None:
        self.assertTrue(SettingsService.update_setting(FLAG, value).is_ok())

    def post(self, url: str) -> Any:
        with patch("django_q.tasks.async_task"):
            return self.client.post(url)

    def chain_jobs(self) -> list[VirtualminProvisioningJob]:
        return list(
            VirtualminProvisioningJob.objects.filter(
                operation="backup_domain", parameters__chain_role__in=("base", "differential")
            )
        )

    def button_for(self, page: str, url: str) -> str:
        match = re.search(rf"<button[^>]*hx-post=\"{re.escape(url)}\"[^>]*>.*?</button>", page, re.DOTALL)
        self.assertIsNotNone(match, f"no button posts to {url}")
        return match.group(0) if match else ""


class AccountPageTests(StaffActionCase):
    def test_with_the_flag_on_both_actions_are_offered_with_plain_labels_and_a_confirmation(self) -> None:
        self.set_flag(True)
        page = self.client.get(self.detail).content.decode()
        base_button, differential_button = self.button_for(page, self.base_url), self.button_for(page, self.differential_url)
        self.assertIn("Take base backup", base_button)
        self.assertIn("Take differential backup", differential_button)
        for button in (base_button, differential_button):
            self.assertIn("hx-confirm=", button)
            self.assertIn("X-CSRFToken", button, "a POST needs the token")
        self.assertIn("complete backup", base_button)
        self.assertIn("only what changed", differential_button)
        self.assertIn(reverse("provisioning:virtualmin_account_restore_pair", args=[self.account.pk]), page)

    def test_with_the_flag_off_none_of_the_differential_actions_is_offered(self) -> None:
        self.set_flag(False)
        page = self.client.get(self.detail).content.decode()
        self.assertNotIn(self.base_url, page)
        self.assertNotIn(self.differential_url, page)
        self.assertNotIn("Take base backup", page)
        self.assertNotIn(reverse("provisioning:virtualmin_account_restore_pair", args=[self.account.pk]), page)


class TakeActionTests(StaffActionCase):
    def setUp(self) -> None:
        super().setUp()
        self.set_flag(True)

    def test_take_base_queues_a_base_for_the_account_and_opens_its_status(self) -> None:
        response = self.post(self.base_url)
        (job,) = self.chain_jobs()
        self.assertEqual((job.parameters["chain_role"], job.account_id), ("base", self.account.pk))
        self.assertEqual(job.parameters["initiated_by"], "staff:chain-staff@example.com")
        self.assertRedirects(
            response, reverse("provisioning:virtualmin_job_status", args=[job.pk]), fetch_redirect_response=False
        )

    def test_take_differential_extends_the_live_base(self) -> None:
        base = self.live_chain(self.account, epoch=2)
        self.post(self.differential_url)
        (job,) = [queued for queued in self.chain_jobs() if queued.status == "pending"]
        self.assertEqual(job.parameters["chain_role"], "differential")
        self.assertEqual(job.parameters["base_job_id"], str(base.pk))

    def test_take_differential_without_a_live_base_says_so_and_queues_nothing(self) -> None:
        response = self.client.post(self.differential_url, follow=True)
        self.assertEqual(self.chain_jobs(), [])
        self.assertContains(response, "base backup")

    def test_with_the_flag_off_a_post_is_refused_and_queues_nothing(self) -> None:
        self.set_flag(False)
        for url in (self.base_url, self.differential_url):
            with self.subTest(url=url):
                response = self.client.post(url, follow=True)
                self.assertEqual(self.chain_jobs(), [])
                self.assertContains(response, "Differential backups are not enabled")

    def test_an_account_with_another_operation_is_refused(self) -> None:
        self._job(self.account, "backup_domain", "running")
        self.post(self.base_url)
        self.assertEqual(self.chain_jobs(), [])

    def test_only_a_post_is_accepted(self) -> None:
        for url in (self.base_url, self.differential_url):
            self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.chain_jobs(), [])

    def test_only_staff_may_take_them(self) -> None:
        customer = User.objects.create_user(email="not-staff@example.com", password="not-staff-password")
        for user in (None, customer):
            self.client.logout()
            if user is not None:
                self.client.force_login(user)
            for url in (self.base_url, self.differential_url):
                with self.subTest(user=getattr(user, "email", None), url=url):
                    response = self.post(url)
                    self.assertIn(response.status_code, (302, 403))
                    self.assertEqual(self.chain_jobs(), [])

    def test_the_bulk_page_offers_no_base_or_differential_action(self) -> None:
        page = self.client.get(reverse("provisioning:virtualmin_bulk_actions")).content.decode()
        self.assertNotRegex(page, r"(?i)differential")
        self.assertNotRegex(page, r"(?i)\bbase backup")

    def test_a_bulk_backup_is_always_a_standalone_backup(self) -> None:
        with patch("django_q.tasks.async_task"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(
                reverse("provisioning:virtualmin_bulk_actions"),
                {
                    "action": "backup",
                    "selected_accounts": [str(self.account.pk)],
                    "backup_type": "full",
                    "chain_role": "base",
                    "confirm_bulk_action": "on",
                },
            )
        self.assertEqual(self.chain_jobs(), [])


class CliTests(StaffActionCase):
    def run_command(self, *args: str) -> str:
        out = StringIO()
        # The command runs the job in-process, which needs autocommit; the test case's own
        # transaction is not one, so the check that guards real runs is told it is outside.
        with patch("apps.provisioning.virtualmin_service.is_outside_transaction", return_value=True):
            call_command("virtualmin_backup", *args, stdout=out)
        return out.getvalue()

    def complete_inline(self) -> Any:
        """Stand in for the worker the CLI runs in-process: mark the admitted job completed."""

        def finish(job_id: str) -> dict[str, Any]:
            VirtualminProvisioningJob.objects.filter(pk=job_id).update(status="completed", result={"backup_id": "cli-1"})
            return {"status": "completed"}

        return patch.object(virtualmin_tasks, "run_virtualmin_backup", side_effect=finish)

    def test_a_chain_role_with_the_flag_off_is_refused_and_creates_nothing(self) -> None:
        self.set_flag(False)
        for role in ("base", "differential"):
            with self.subTest(role=role), self.assertRaisesRegex(CommandError, "disabled"):
                self.run_command("backup", self.account.domain, "--chain-role", role)
        self.assertEqual(VirtualminProvisioningJob.objects.count(), 0)

    def test_a_base_is_admitted_through_the_job_layer(self) -> None:
        self.set_flag(True)
        with self.complete_inline():
            output = self.run_command("backup", self.account.domain, "--chain-role", "base")
        (job,) = self.chain_jobs()
        self.assertEqual((job.parameters["chain_role"], job.parameters["initiated_by"]), ("base", "cli"))
        self.assertIn("Backup ID: cli-1", output)

    def test_a_differential_without_a_live_base_is_refused(self) -> None:
        self.set_flag(True)
        with self.assertRaisesRegex(CommandError, "base backup"):
            self.run_command("backup", self.account.domain, "--chain-role", "differential")

    def test_an_unknown_role_is_refused_by_the_parser(self) -> None:
        with self.assertRaises(CommandError):
            self.run_command("backup", self.account.domain, "--chain-role", "incremental")

    def test_a_backup_without_a_role_stays_standalone(self) -> None:
        self.set_flag(True)
        with self.complete_inline():
            self.run_command("backup", self.account.domain)
        (job,) = VirtualminProvisioningJob.objects.filter(operation="backup_domain")
        self.assertEqual(job.parameters["chain_role"], "standalone")

    def test_a_pair_restore_works_whatever_the_flag_says(self) -> None:
        for flag in (True, False):
            with self.subTest(flag=flag):
                self.set_flag(flag)
                with patch.object(
                    VirtualminBackupManagementService, "create_pair_restore_job", autospec=True
                ) as admit:
                    admit.return_value = Ok(VirtualminProvisioningJob(pk=None, result={"restore_id": "r-9"}))
                    output = self.run_command(
                        "restore", self.account.domain, "base-1", "--differential-backup-id", "diff-1", "--force-restore"
                    )
                call = admit.call_args
                self.assertEqual(call.args[1:4], (self.account, "base-1", "diff-1"))
                self.assertEqual(
                    {key: call.kwargs[key] for key in ("force_restore", "execute_inline", "initiated_by")},
                    {"force_restore": True, "execute_inline": True, "initiated_by": "cli"},
                )
                self.assertIn("Restore ID: r-9", output)

    def test_a_pair_restore_must_be_confirmed_and_restores_every_component(self) -> None:
        self.set_flag(True)
        with self.assertRaisesRegex(CommandError, "confirmed"):
            self.run_command("restore", self.account.domain, "base-1", "--differential-backup-id", "diff-1")
        with self.assertRaisesRegex(CommandError, "every component"):
            self.run_command(
                "restore",
                self.account.domain,
                "base-1",
                "--differential-backup-id",
                "diff-1",
                "--force-restore",
                "--no-email",
            )
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
