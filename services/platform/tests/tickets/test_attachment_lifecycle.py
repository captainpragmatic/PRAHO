"""An attachment's file lives exactly as long as its row.

File storage is not transactional: a file written inside a transaction that rolls back stays on
disk with no row naming it, and a row deleted by a ticket's CASCADE leaves its file behind. The
reply paths write files only once nothing they know of can still roll the reply back, delete what
they wrote when a row cannot be saved, and a deleted row deletes its file once the delete commits.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django_q.models import Schedule

from apps.common.media_sweep import ATTACHMENT_NAME
from apps.customers.models import Customer
from apps.tickets.models import Ticket, TicketAttachment, TicketComment
from apps.tickets.tasks import setup_ticket_scheduled_tasks
from apps.users.models import CustomerMembership, User

TEXT = b"Timeout at 12:00 UTC\n"


class AttachmentLifecycleTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        setting = override_settings(MEDIA_ROOT=directory.name)
        setting.enable()
        self.addCleanup(setting.disable)
        self.media = Path(directory.name)
        self.user = User.objects.create_user(email="lifecycle@example.test", password="Lifecycle-secure123!")
        self.customer = Customer.objects.create(name="Lifecycle Company", status="active")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_primary=True)
        self.ticket = Ticket.objects.create(customer=self.customer, title="Files", description="x", status="open")

    def _stored_files(self) -> list[Path]:
        return [path for path in self.media.rglob("*") if path.is_file()]

    def _reply(self, *names: str) -> None:
        self.client.force_login(self.user)
        self.client.post(
            reverse("tickets:reply", args=[self.ticket.pk]),
            {"reply": "Files", "attachments": [SimpleUploadedFile(name, TEXT) for name in names]},
        )

    def test_staff_attachment_is_stored_under_a_random_name_in_tickets_attachments(self) -> None:
        self._reply("Ion Popescu contract.txt")

        attachment = TicketAttachment.objects.get(ticket=self.ticket)
        # The sweeper deletes only names of this shape: a stored name it does not recognise is never swept.
        self.assertIsNotNone(ATTACHMENT_NAME.fullmatch(attachment.file.name), attachment.file.name)

    def test_status_error_leaves_no_attachment_file(self) -> None:
        with patch(
            "apps.tickets.views.TicketStatusService.handle_customer_reply", side_effect=ValueError("not now")
        ):
            self._reply("log.txt")

        self.assertFalse(TicketComment.objects.filter(ticket=self.ticket).exists())
        self.assertFalse(TicketAttachment.objects.exists())
        self.assertEqual(self._stored_files(), [])

    def test_row_save_failure_deletes_the_registered_file(self) -> None:
        original_save = TicketAttachment.save
        calls = []

        def save_then_fail_the_second(attachment: TicketAttachment, *args: object, **kwargs: object) -> None:
            calls.append(attachment.file.name)
            if len(calls) == 2:  # The second of two files
                raise RuntimeError("row save failed")
            original_save(attachment, *args, **kwargs)

        with (
            patch.object(TicketAttachment, "save", save_then_fail_the_second),
            self.assertRaises(RuntimeError),
        ):
            self._reply("first.txt", "second.txt")

        self.assertEqual(len(calls), 2)
        self.assertFalse(TicketAttachment.objects.exists())
        self.assertEqual(self._stored_files(), [], "both written files are deleted, not only the failing one")

    def test_deleting_a_ticket_deletes_attachment_files(self) -> None:
        attachment = TicketAttachment(ticket=self.ticket, filename="log.txt", file_size=len(TEXT))
        attachment.file.save("log.txt", ContentFile(TEXT), save=False)
        attachment.save()
        stored = self.media / attachment.file.name

        with self.captureOnCommitCallbacks(execute=True):
            self.ticket.delete()
            self.assertTrue(stored.exists(), "the file outlives the row until the delete commits")

        self.assertFalse(stored.exists())

    def test_a_rolled_back_delete_keeps_the_file(self) -> None:
        attachment = TicketAttachment(ticket=self.ticket, filename="log.txt", file_size=len(TEXT))
        attachment.file.save("log.txt", ContentFile(TEXT), save=False)
        attachment.save()

        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            self.ticket.delete()

        self.assertEqual(len(callbacks), 1)
        self.assertTrue((self.media / attachment.file.name).exists())


class MediaSweepScheduleTests(TestCase):
    def test_setup_with_auto_close_present_creates_the_sweeper(self) -> None:
        Schedule.objects.create(
            name="tickets-auto-close-inactive",
            func="apps.tickets.tasks.auto_close_inactive_tickets",
            schedule_type=Schedule.HOURLY,
        )

        result = setup_ticket_scheduled_tasks()

        sweeper = Schedule.objects.get(func="apps.common.media_sweep.sweep_orphaned_media")
        self.assertEqual(sweeper.schedule_type, Schedule.DAILY)
        self.assertEqual(result, {"auto_close_inactive": "already_exists", "sweep_orphaned_media": "created"})
        self.assertEqual(setup_ticket_scheduled_tasks()["sweep_orphaned_media"], "already_exists")
