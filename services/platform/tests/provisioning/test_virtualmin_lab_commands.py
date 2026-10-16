"""The Virtualmin lab commands refuse non-lab settings, and the lab transport
adapts only the lab node names."""

from __future__ import annotations

import stat
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.common import outbound_http
from apps.provisioning.management.commands._virtualmin_lab import (
    LAB_STAFF_EMAIL,
    LabNode,
    LabState,
    enable_lab_features,
    ensure_lab_staff,
    lab_transport,
    read_env_file,
    run_queued_once,
)
from apps.settings.services import SettingsService
from apps.users.models import User


def _state() -> LabState:
    return LabState(
        state_dir="/nonexistent",
        nodes=(LabNode("vm-a", "vmlab-a", "vm-a.praho.test", "dev-sha-lab-ro-vmla-001", 10101, 2522),),
        known_hosts="/nonexistent/known_hosts",
        s3_endpoint="http://127.0.0.1:19000",
        bucket="praho-backups",
        domain="roundtrip.praho.test",
        domain_user="roundtrip",
    )


class LabCommandRefusalTests(SimpleTestCase):
    def test_commands_refuse_outside_lab_settings(self) -> None:
        for command in (
            "virtualmin_lab_bootstrap",
            "virtualmin_lab_roundtrip",
            "virtualmin_lab_checks",
            "virtualmin_lab_runserver",
        ):
            for module, debug in (
                ("config.settings.prod", False),
                ("config.settings.staging", False),
                ("config.settings.dev", True),
                ("config.settings.lab", False),
            ):
                with (
                    self.subTest(command=command, module=module, debug=debug),
                    override_settings(SETTINGS_MODULE=module, DEBUG=debug),
                    self.assertRaisesMessage(CommandError, "Refusing to run"),
                ):
                    call_command(command)


@override_settings(SETTINGS_MODULE="config.settings.lab", DEBUG=True)
class LabTransportScopeTests(SimpleTestCase):
    def test_only_lab_names_resolve_to_loopback(self) -> None:
        with patch.object(outbound_http, "_resolve_dns", return_value=["203.0.113.9"]) as real:
            with lab_transport(_state()):
                self.assertEqual(outbound_http._resolve_dns("vm-a.praho.test", 10101), ["127.0.0.1"])
                self.assertEqual(outbound_http._resolve_dns("vm-a.praho.test.evil", 10101), ["203.0.113.9"])
            real.assert_called_once_with("vm-a.praho.test.evil", 10101)
            # Restored on exit.
            self.assertEqual(outbound_http._resolve_dns("vm-a.praho.test", 10101), ["203.0.113.9"])


@override_settings(SETTINGS_MODULE="config.settings.lab", DEBUG=True)
class LabRunserverTests(SimpleTestCase):
    """The lab server must run inside the lab transport: a bare runserver cannot reach a node."""

    def test_runserver_runs_inside_the_lab_transport(self) -> None:
        seen: dict[str, object] = {}

        def fake_runserver(name: str, *args: str, **options: object) -> None:
            seen["name"], seen["args"] = name, args
            seen["resolved"] = outbound_http._resolve_dns("vm-a.praho.test", 10101)

        with (
            patch("apps.provisioning.management.commands.virtualmin_lab_runserver.load_state", return_value=_state()),
            patch(
                "apps.provisioning.management.commands.virtualmin_lab_runserver.call_command",
                side_effect=fake_runserver,
            ),
            patch.object(outbound_http, "_resolve_dns", return_value=["203.0.113.9"]),
        ):
            call_command("virtualmin_lab_runserver", "127.0.0.1:8710", "--noreload")
            after = outbound_http._resolve_dns("vm-a.praho.test", 10101)

        self.assertEqual(seen["name"], "runserver")
        self.assertEqual(seen["args"], ("127.0.0.1:8710", "--noreload"))
        self.assertEqual(seen["resolved"], ["127.0.0.1"], "the server must resolve the lab names to the published ports")
        self.assertEqual(after, ["203.0.113.9"], "the transport is lifted when the server stops")

    def _serve(self, *flags: str) -> dict[str, object]:
        """Run the command with a stand-in worker and a stand-in runserver; report what the worker saw."""
        seen: dict[str, object] = {}
        worker_started = threading.Event()

        def fake_worker(stop: threading.Event) -> None:
            seen["resolved"] = outbound_http._resolve_dns("vm-a.praho.test", 10101)
            worker_started.set()
            stop.wait(5)

        def fake_runserver(*args: str, **options: object) -> None:
            seen["started_while_serving"] = worker_started.wait(0.5)

        module = "apps.provisioning.management.commands.virtualmin_lab_runserver"
        with (
            patch(f"{module}.load_state", return_value=_state()),
            patch(f"{module}.call_command", side_effect=fake_runserver),
            patch(f"{module}._work", side_effect=fake_worker),
            patch.object(outbound_http, "_resolve_dns", return_value=["203.0.113.9"]),
        ):
            call_command("virtualmin_lab_runserver", "127.0.0.1:8710", "--noreload", *flags)
        return seen

    def test_the_queue_is_worked_inside_the_transport_and_stops_with_the_server(self) -> None:
        seen = self._serve()

        self.assertTrue(seen["started_while_serving"])
        self.assertEqual(seen["resolved"], ["127.0.0.1"], "a lab task must reach the nodes")

    def test_no_worker_flag_leaves_the_queue_alone(self) -> None:
        seen = self._serve("--no-worker")

        self.assertFalse(seen["started_while_serving"])


class LabWorkerLoopTests(SimpleTestCase):
    def test_a_failed_pass_does_not_end_the_worker(self) -> None:
        from apps.provisioning.management.commands import virtualmin_lab_runserver as command  # noqa: PLC0415

        stop = threading.Event()
        passes: list[int] = []

        def one_pass() -> list[object]:
            passes.append(1)
            if len(passes) == 1:
                raise RuntimeError("the node was busy")
            stop.set()
            return []

        with (
            patch.object(command, "run_queued_once", side_effect=one_pass),
            patch.object(command, "WORKER_POLL_SECONDS", 0),
            patch.object(command, "close_old_connections"),
            self.assertLogs(command.logger, level="ERROR"),
        ):
            command._work(stop)

        self.assertEqual(len(passes), 2)


class LabStaffTests(TestCase):
    """A developer (and the browser smoke tests) need a staff login in the lab database."""

    def test_staff_user_can_log_in_and_the_credentials_are_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ensure_lab_staff(Path(directory))
            env_path = Path(directory) / "staff.env"
            values = read_env_file(env_path)
            self.assertEqual(stat.S_IMODE(env_path.stat().st_mode), 0o600)

        user = User.objects.get(email=LAB_STAFF_EMAIL)
        self.assertEqual(values["LAB_STAFF_EMAIL"], LAB_STAFF_EMAIL)
        self.assertTrue(user.check_password(values["LAB_STAFF_PASSWORD"]))
        self.assertTrue(user.is_staff and user.is_superuser and user.is_active)
        self.assertEqual(user.staff_role, "admin")

    def test_rerun_rotates_the_password_and_keeps_one_user(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ensure_lab_staff(Path(directory))
            first = read_env_file(Path(directory) / "staff.env")["LAB_STAFF_PASSWORD"]
            ensure_lab_staff(Path(directory))
            second = read_env_file(Path(directory) / "staff.env")["LAB_STAFF_PASSWORD"]

        self.assertNotEqual(first, second)
        user = User.objects.get(email=LAB_STAFF_EMAIL)
        self.assertTrue(user.check_password(second))
        self.assertFalse(user.check_password(first))
        self.assertEqual(User.objects.filter(email=LAB_STAFF_EMAIL).count(), 1)


CALLS: list[object] = []


def record_call(value: object) -> str:
    CALLS.append(value)
    return f"ran {value}"


def failing_call() -> None:
    raise RuntimeError("the task failed")


def _queue(func: str, *args: object) -> OrmQ:
    package = {"id": func, "func": func, "args": args, "kwargs": {}}
    return OrmQ.objects.create(key="praho-cluster", payload=SignedPackage.dumps(package))


class LabWorkerTests(TestCase):
    """The lab has no Django-Q worker (its spawned processes would lose the lab transport): one pass plays it."""

    MODULES = (__name__,)

    def setUp(self) -> None:
        CALLS.clear()

    def test_a_queued_task_is_run_once_and_leaves_the_queue(self) -> None:
        _queue(f"{__name__}.record_call", "backup")

        runs = run_queued_once(self.MODULES)

        self.assertEqual([(run.name, run.result, run.error) for run in runs], [("record_call", "ran backup", "")])
        self.assertEqual(CALLS, ["backup"])
        self.assertEqual(OrmQ.objects.count(), 0)
        self.assertEqual(run_queued_once(self.MODULES), [], "a task that has run is not run again")

    def test_a_task_outside_the_hosting_modules_is_discarded_unrun(self) -> None:
        _queue("apps.notifications.tasks.send_email", "x")

        self.assertEqual(run_queued_once(self.MODULES), [])
        self.assertEqual(OrmQ.objects.count(), 0)

    def test_a_failing_task_is_recorded_and_does_not_stop_the_pass(self) -> None:
        _queue(f"{__name__}.failing_call")
        _queue(f"{__name__}.record_call", "after")

        runs = run_queued_once(self.MODULES)

        self.assertEqual([run.name for run in runs], ["failing_call", "record_call"])
        self.assertIn("the task failed", runs[0].error)
        self.assertEqual(CALLS, ["after"])

    def test_a_row_another_worker_already_took_is_skipped(self) -> None:
        row = _queue(f"{__name__}.record_call", "taken")
        stale = list(OrmQ.objects.all())
        OrmQ.objects.filter(pk=row.pk).delete()

        with patch("apps.provisioning.management.commands._virtualmin_lab.OrmQ.objects.order_by", return_value=stale):
            self.assertEqual(run_queued_once(self.MODULES), [])
        self.assertEqual(CALLS, [])


@override_settings(SETTINGS_MODULE="config.settings.lab", DEBUG=True)
class LabFeaturesTests(TestCase):
    """The lab server turns on the opt-in hosting features, so a browser can reach them."""

    FLAGS = (
        "provisioning.migration_enabled",
        "infrastructure.drain_enabled",
        "provisioning.incremental_backups_enabled",
    )

    def test_enable_lab_features_switches_the_opt_in_flags_on(self) -> None:
        for key in self.FLAGS:
            self.assertFalse(SettingsService.get_setting(key), key)

        enable_lab_features()

        for key in self.FLAGS:
            self.assertIs(SettingsService.get_setting(key), True, key)

    def test_the_server_enables_them_before_it_serves_and_only_when_asked(self) -> None:
        seen: list[bool] = []

        def fake_runserver(*args: str, **options: object) -> None:
            seen.append(bool(SettingsService.get_setting("provisioning.incremental_backups_enabled")))

        module = "apps.provisioning.management.commands.virtualmin_lab_runserver"
        with (
            patch(f"{module}.load_state", return_value=_state()),
            patch(f"{module}.call_command", side_effect=fake_runserver),
        ):
            call_command("virtualmin_lab_runserver", "--noreload", "--no-worker")
            call_command("virtualmin_lab_runserver", "--noreload", "--no-worker", "--features")

        self.assertEqual(seen, [False, True])
