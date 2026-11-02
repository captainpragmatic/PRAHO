"""The opt-in lab worker runs only maintenance work belonging to its disposable fixture."""

from datetime import timedelta
from unittest.mock import patch

from django.core import mail
from django.test import TestCase, override_settings
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.customers.models import Customer
from apps.infrastructure.node_maintenance_models import NodeMaintenanceDelivery, NodeMaintenanceWindow
from apps.notifications.models import EmailLog, EmailTemplate
from apps.provisioning.management.commands._virtualmin_lab import run_queued_once
from apps.provisioning.service_models import Service
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture

TICK = "apps.infrastructure.node_maintenance_tasks.tick_node_maintenance"
SEND = "apps.notifications.tasks.send_email_task"


def queue(func: str, *args: object, **kwargs: object) -> OrmQ:
    return OrmQ.objects.create(
        key="maintenance-lab", payload=SignedPackage.dumps({"id": func, "func": func, "args": args, "kwargs": kwargs})
    )


@override_settings(
    SETTINGS_MODULE="config.settings.lab",
    DEBUG=True,
    VIRTUALMIN_MAINTENANCE_LAB=True,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    Q_CLUSTER={"name": "maintenance-lab", "orm": "default", "retry": 100000},
)
class MaintenanceLabWorkerTests(MaintenanceAdmissionFixture, TestCase):
    def scope(self, window: NodeMaintenanceWindow) -> dict[str, object]:
        return {
            "node_ids": [str(self.node.pk)],
            "customer_ids": [self.customer.pk],
            "service_ids": [self.account.service_id],
            "window_ids": [str(window.pk)],
        }

    def test_exact_owned_tick_runs_but_global_foreign_and_provider_work_stay_queued(self) -> None:
        owned = self.start(self.window())
        due = owned.ends_at + timedelta(seconds=1)
        prior_rows = set(OrmQ.objects.values_list("pk", flat=True))
        allowed = queue(TICK, window_ids=[str(owned.pk)])
        protected = [
            queue(TICK),
            queue(TICK, window_ids=None),
            queue(TICK, window_ids=[]),
            queue(TICK, window_ids=[str(self.node.pk)]),
            queue("apps.infrastructure.tasks.reboot_node_task", -1),
            queue("apps.provisioning.virtualmin_tasks.run_virtualmin_backup", "unowned-backup"),
        ]

        with patch("apps.infrastructure.node_maintenance_tasks.timezone.now", return_value=due):
            runs = run_queued_once(maintenance_scope=self.scope(owned))

        self.assertEqual([(run.func, run.result["overran"], run.error) for run in runs], [(TICK, 1, "")])
        self.assertFalse(OrmQ.objects.filter(pk=allowed.pk).exists())
        self.assertEqual(set(OrmQ.objects.values_list("pk", flat=True)), prior_rows | {row.pk for row in protected})
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=owned.pk).status, "overran")

    def test_linked_owned_email_uses_actual_delivery_while_unrelated_mail_is_preserved(self) -> None:
        self.customer.primary_email = "owned-maintenance@example.test"
        self.customer.save(update_fields=["primary_email"])
        for locale in ("en", "ro"):
            EmailTemplate.objects.update_or_create(
                key="maintenance_scheduled",
                locale=locale,
                defaults={"subject": "Maintenance", "body_text": "{{ customer_note }}", "category": "maintenance"},
            )
        with self.captureOnCommitCallbacks(execute=True):
            owned = self.window()
        intent = NodeMaintenanceDelivery.objects.get(window=owned)
        self.assertIsNotNone(intent.email_log_id)
        self.assertTrue(
            any(
                row.task.get("func") == SEND
                and row.task.get("kwargs", {}).get("email_log_id") == str(intent.email_log_id)
                for row in OrmQ.objects.all()
            ),
            "The actual email producer must publish its broker row",
        )
        unrelated = EmailLog.objects.create(to_addr="unrelated@example.test", subject="Unrelated", body_text="Preserve")
        protected = queue(SEND, str(unrelated.pk))

        runs = run_queued_once(maintenance_scope=self.scope(owned))

        self.assertEqual([run.func for run in runs], [SEND])
        self.assertFalse(runs[0].error, runs[0].error)
        self.assertTrue(runs[0].result["success"], runs[0].result)
        self.assertEqual([message.to for message in mail.outbox], [[self.customer.primary_email]])
        self.assertTrue(OrmQ.objects.filter(pk=protected.pk).exists())
        unrelated.refresh_from_db()
        self.assertEqual(unrelated.status, "queued")

    def test_a_foreign_customer_binding_refuses_before_broker_row_deletion(self) -> None:
        owned = self.window()
        row = queue(TICK, window_ids=[str(owned.pk)])
        scope = self.scope(owned)
        scope["customer_ids"] = [self.customer.pk + 1000]

        self.assertEqual(run_queued_once(maintenance_scope=scope), [])

        self.assertTrue(OrmQ.objects.filter(pk=row.pk).exists())
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=owned.pk).status, "scheduled")

    def test_falsey_malformed_tick_arguments_stay_queued_before_any_dispatch(self) -> None:
        owned = self.window()
        rows = [
            OrmQ.objects.create(
                key="maintenance-lab",
                payload=SignedPackage.dumps(
                    {
                        "func": TICK,
                        "args": args,
                        "kwargs": {"window_ids": [str(owned.pk)]},
                    }
                ),
            )
            for args in (None, False, 0, "")
        ]
        failure = None
        try:
            runs = run_queued_once(maintenance_scope=self.scope(owned))
        except TypeError as error:
            failure = str(error)
            runs = []

        self.assertEqual(
            set(OrmQ.objects.filter(pk__in=[row.pk for row in rows]).values_list("pk", flat=True)),
            {row.pk for row in rows},
            f"A malformed tick was removed before its arguments were qualified: {failure}",
        )
        self.assertIsNone(failure)
        self.assertEqual(runs, [])

    def test_a_new_undeclared_placement_cannot_publish_foreign_notice_intents(self) -> None:
        for locale in ("en", "ro"):
            EmailTemplate.objects.get_or_create(
                key="maintenance_scheduled",
                locale=locale,
                defaults={"subject": "Maintenance", "body_text": "Maintenance", "category": "maintenance"},
            )
        owned = self.window()
        scope = self.scope(owned)
        foreign = Customer.objects.create(name="Outside fixture", primary_email="outside@example.test")
        added = self.account_on_node("outside-fixture.example.test")
        Service.objects.filter(pk=added.service_id).update(customer=foreign)
        row = queue(TICK, window_ids=[str(owned.pk)])

        runs = run_queued_once(maintenance_scope=scope)

        self.assertFalse(NodeMaintenanceDelivery.objects.filter(window=owned, customer=foreign).exists())
        self.assertTrue(OrmQ.objects.filter(pk=row.pk).exists())
        self.assertEqual(runs, [])
