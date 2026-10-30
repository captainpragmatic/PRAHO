"""The node collector runs independently of Django and never invents traffic."""

import importlib.util
import json
import sqlite3
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier, BrokenBarrierError
from unittest.mock import patch

from django.test import SimpleTestCase

SOURCE = Path(__file__).resolve().parents[2] / "infrastructure/ansible/playbooks/files/praho_usage.py"


class UsageCollectorTests(SimpleTestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("praho_usage", SOURCE)
        self.collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.collector)
        self.directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.object(self.collector, "STATE_ROOT", Path(self.directory)))

    def node_fixture(self):
        root = Path(self.directory)
        home = root / "home"
        home.mkdir(exist_ok=True)
        logs = root / "logs"
        logs.mkdir(exist_ok=True)
        ledger = self.collector.Ledger(root / "usage.sqlite3")
        self.addCleanup(ledger.close)
        account = {"id": "42", "domain": "example.test", "username": "example", "home": str(home),
                   "databases": [], "members": ["42"], "binding_verified": True, "mailboxes": 0}
        return ledger, logs, account

    def refresh_fixture(self, ledger, logs, accounts, observed):
        bindings_file = Path(self.directory) / "bindings.json"
        bindings = json.loads(bindings_file.read_text()) if bindings_file.exists() else {"installation": "node", "accounts": {}}
        for account in accounts:
            account.setdefault("binding_started_at", observed)
            bindings["accounts"][account["id"]] = {
                "verified": account.get("binding_verified") is True,
                "started_at": account["binding_started_at"], "last_seen_at": observed,
            }
        bindings_file.write_text(json.dumps(bindings))
        with (
            patch.object(self.collector, "LOG_ROOT", logs),
            patch.object(self.collector, "utc_now", return_value=observed),
            patch.object(self.collector, "read_metadata", return_value=json.dumps({"accounts": accounts}).encode()),
        ):
            self.collector.refresh(ledger)

    def snapshot_segment(self, ledger, start, end):
        return self.collector.export_snapshot(ledger, "node", {"intervals": [
            {"id": "interval", "domain_id": "42", "domain": "example.test", "start": start, "end": end}
        ]})["records"][0]["segments"][0]

    def test_scan_starts_before_metadata_measures_database_sizes(self):
        ledger, logs, account = self.node_fixture()
        (logs / "usage.log").touch()
        timestamps = [f"2026-10-01T00:0{minute}:00+00:00" for minute in range(4)]
        with (
            patch.object(self.collector, "LOG_ROOT", logs),
            patch.object(self.collector, "utc_now", side_effect=timestamps),
            patch.object(self.collector, "read_metadata", return_value=json.dumps({"accounts": [account]}).encode()),
        ):
            self.collector.refresh(ledger)
        row = json.loads(ledger.connection.execute("SELECT payload FROM gauges").fetchone()[0])
        self.assertEqual(row["scan_started_at"], timestamps[0])
        self.assertEqual(row["identity_observed_at"], timestamps[0])

    def test_collection_resumes_after_expensive_accounts_instead_of_starving_the_tail(self):
        ledger, logs, account = self.node_fixture()
        (logs / "usage.log").touch()
        other = {**account, "id": "43", "domain": "second.test"}
        clock = [0.0]

        def expensive(_home, _databases, **_kwargs):
            clock[0] = 1000
            return {"disk_files_bytes": 12, "disk_db_bytes": 0, "disk_total_bytes": 12, "databases": 0}

        with (
            patch.object(self.collector.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(self.collector, "disk_measurement", side_effect=expensive),
        ):
            self.refresh_fixture(ledger, logs, [account, other], "2026-10-01T00:00:00+00:00")
            self.assertIsNone(json.loads(ledger.connection.execute("SELECT payload FROM gauges WHERE domain='43'").fetchone()[0])["disk_total_bytes"])
            clock[0] = 0
            self.refresh_fixture(ledger, logs, [account, other], "2026-10-01T01:00:00+00:00")
        self.assertEqual(json.loads(ledger.connection.execute("SELECT payload FROM gauges WHERE domain='43'").fetchone()[0])["disk_total_bytes"], 12)

    def test_export_uses_request_time_top_identity_not_current_members(self):
        ledger, logs, account = self.node_fixture()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        epoch = self.collector.epoch_us(start)
        (logs / "usage.log").write_text(f"v1 node 42 {epoch} 100\nv1 node 43 {epoch} 200\n")
        account["members"] = ["42", "43"]
        self.refresh_fixture(ledger, logs, [account], start)
        self.refresh_fixture(ledger, logs, [account], end)
        self.assertEqual(self.snapshot_segment(ledger, start, end)["bytes"], 100)

    def test_invalid_record_does_not_poison_future_intervals_forever(self):
        ledger, logs, account = self.node_fixture()
        times = [f"2026-10-01T00:0{minute}:00+00:00" for minute in range(4)]
        log = logs / "usage.log"
        log.touch()
        self.refresh_fixture(ledger, logs, [account], times[0])
        log.write_text("not-a-usage-record\n")
        self.refresh_fixture(ledger, logs, [account], times[1])
        with log.open("a") as stream:
            stream.write(f"v1 node 42 {self.collector.epoch_us(times[2])} 120\n")
        self.refresh_fixture(ledger, logs, [account], times[3])
        self.assertFalse(self.snapshot_segment(ledger, times[0], times[3])["complete"])
        segment = self.snapshot_segment(ledger, times[2], times[3])
        self.assertTrue(segment["complete"])
        self.assertEqual(segment["bytes"], 120)

    def test_unmanaged_rotation_is_not_reported_as_complete(self):
        ledger, logs, account = self.node_fixture()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        log = logs / "usage.log"
        log.write_text(f"v1 node 42 {self.collector.epoch_us(start)} 100\n")
        self.refresh_fixture(ledger, logs, [account], start)
        log.rename(Path(self.directory) / "lost-rotation")
        log.write_text(f"v1 node 42 {self.collector.epoch_us(end)} 200\n")
        self.refresh_fixture(ledger, logs, [account], end)
        self.assertFalse(self.snapshot_segment(ledger, start, end)["complete"])

    def test_missing_binding_does_not_hide_an_independent_disk_measurement(self):
        ledger, logs, account = self.node_fixture()
        (logs / "usage.log").touch()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        account["binding_verified"] = False
        self.refresh_fixture(ledger, logs, [account], start)
        self.refresh_fixture(ledger, logs, [account], end)
        snapshot = self.collector.export_snapshot(ledger, "node", {"intervals": [
            {"id": "interval", "domain_id": "42", "domain": "example.test", "start": start, "end": end}
        ]})
        self.assertEqual(len(snapshot["records"]), 1)
        self.assertIsInstance(snapshot["records"][0]["disk_total_bytes"], int)
        self.assertFalse(snapshot["records"][0]["segments"][0]["complete"])

    def test_unavailable_disk_does_not_hide_valid_bandwidth(self):
        ledger, logs, account = self.node_fixture()
        (logs / "usage.log").touch()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        account["unavailable"] = True
        self.refresh_fixture(ledger, logs, [account], start)
        self.refresh_fixture(ledger, logs, [account], end)
        snapshot = self.collector.export_snapshot(ledger, "node", {"intervals": [
            {"id": "interval", "domain_id": "42", "domain": "example.test", "start": start, "end": end}
        ]})
        self.assertIsNone(snapshot["records"][0]["disk_total_bytes"])
        self.assertEqual(snapshot["records"][0]["identity_observed_at"], end)
        self.assertTrue(snapshot["records"][0]["segments"][0]["complete"])

    def test_unknown_mailbox_count_does_not_hide_disk_or_bandwidth(self):
        ledger, logs, account = self.node_fixture()
        (logs / "usage.log").touch()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        account["mailboxes"] = None
        self.refresh_fixture(ledger, logs, [account], start)
        self.refresh_fixture(ledger, logs, [account], end)
        row = self.collector.export_snapshot(ledger, "node", {"intervals": [
            {"id": "interval", "domain_id": "42", "domain": "example.test", "start": start, "end": end}
        ]})["records"][0]
        self.assertIsNone(row["mailboxes"])
        self.assertIsInstance(row["disk_total_bytes"], int)
        self.assertTrue(row["segments"][0]["complete"])

    def test_cached_export_clips_requested_end_to_source_observation(self):
        ledger, logs, account = self.node_fixture()
        (logs / "usage.log").touch()
        start, observed, requested = "2026-10-01T00:00:00+00:00", "2026-10-01T01:00:00+00:00", "2026-10-01T01:10:00+00:00"
        self.refresh_fixture(ledger, logs, [account], start)
        self.refresh_fixture(ledger, logs, [account], observed)
        segment = self.snapshot_segment(ledger, start, requested)
        self.assertTrue(segment["complete"])
        self.assertEqual(segment["end"], observed)

    def test_pending_reconciliation_makes_cached_bandwidth_incomplete_until_repaired(self):
        ledger, logs, account = self.node_fixture()
        (logs / "usage.log").touch()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        self.refresh_fixture(ledger, logs, [account], start)
        self.refresh_fixture(ledger, logs, [account], end)
        state = Path(self.directory)
        with patch.object(self.collector, "STATE_ROOT", state):
            for marker in ("reconciliation-pending", "reconciliation-processing"):
                path = state / marker
                path.touch()
                self.assertFalse(self.snapshot_segment(ledger, start, end)["complete"])
                path.unlink()
            self.assertTrue(self.snapshot_segment(ledger, start, end)["complete"])

    def test_missing_identities_expire_without_removing_current_unknown_gauges(self):
        ledger, logs, account = self.node_fixture()
        (logs / "usage.log").touch()
        account["unavailable"] = True
        self.refresh_fixture(ledger, logs, [account], "2026-01-01T00:00:00+00:00")
        other = {**account, "id": "43", "domain": "second.test"}
        self.refresh_fixture(ledger, logs, [other], "2026-05-01T00:00:00+00:00")
        self.assertEqual(ledger.connection.execute("SELECT domain FROM gauges").fetchall(), [("43",)])
        row = self.collector.export_snapshot(ledger, "node", {"intervals": []})["records"][0]
        self.assertTrue(row["present"])
        self.assertIsNone(row["scan_finished_at"])

    def test_binding_repaired_after_cached_collection_cannot_reuse_old_attestation(self):
        ledger, logs, account = self.node_fixture()
        (logs / "usage.log").touch()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        self.refresh_fixture(ledger, logs, [account], start)
        self.refresh_fixture(ledger, logs, [account], end)
        bindings_file = Path(self.directory) / "bindings.json"
        state = json.loads(bindings_file.read_text())
        state["accounts"]["42"]["started_at"] = "2026-10-01T00:02:00+00:00"
        bindings_file.write_text(json.dumps(state))
        self.assertFalse(self.snapshot_segment(ledger, start, end)["complete"])
        bindings_file.unlink()
        self.assertFalse(self.snapshot_segment(ledger, start, end)["complete"])
        bindings_file.write_text("invalid JSON")
        self.assertFalse(self.snapshot_segment(ledger, start, end)["complete"])

    def test_missing_remote_account_is_absent_but_closed_traffic_can_be_read(self):
        ledger, logs, account = self.node_fixture()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        (logs / "usage.log").write_text(f"v1 node 42 {self.collector.epoch_us(start)} 120\n")
        self.refresh_fixture(ledger, logs, [account], start)
        self.refresh_fixture(ledger, logs, [], end)
        snapshot = self.collector.export_snapshot(ledger, "node", {"intervals": [
            {"id": "closed", "domain_id": "42", "domain": "example.test", "start": start, "end": end}
        ]})
        row = snapshot["records"][0]
        self.assertFalse(row["present"])
        self.assertEqual(row["identity_observed_at"], start)
        self.assertEqual(row["segments"][0]["bytes"], 120)
        self.assertTrue(row["segments"][0]["complete"])
        self.assertEqual(self.collector.export_snapshot(ledger, "node", {"intervals": []})["records"], [])

    def test_unbound_child_identity_cannot_silently_become_zero_parent_usage(self):
        ledger, logs, account = self.node_fixture()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        account["members"] = ["42", "43"]
        account["binding_started_at"] = start
        (logs / "usage.log").write_text(f"v1 node 43 {self.collector.epoch_us(start)} 120\n")
        self.refresh_fixture(ledger, logs, [account], start)
        self.refresh_fixture(ledger, logs, [account], end)
        self.assertFalse(self.snapshot_segment(ledger, start, end)["complete"])

    def test_rotation_refuses_an_uncommitted_partial_line(self):
        ledger, logs, _account = self.node_fixture()
        log = logs / "usage.log"
        log.write_text("v1 node 42 100 12")
        with patch.object(self.collector, "LOG_ROOT", logs):
            with self.assertRaises(TimeoutError):
                self.collector.prepare_rotation(ledger, deadline=time.monotonic() + 2)
            self.assertIsNone(ledger.value("rotation_pending"))
            with log.open("a") as stream:
                stream.write("\n")
            self.collector.prepare_rotation(ledger, deadline=time.monotonic() + 2)
            self.assertIsNotNone(ledger.value("rotation_pending"))

    def test_managed_rotation_preserves_verified_lineage(self):
        ledger, logs, account = self.node_fixture()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        log = logs / "usage.log"
        log.write_text(f"v1 node 42 {self.collector.epoch_us(start)} 120\n")
        self.refresh_fixture(ledger, logs, [account], start)
        with patch.object(self.collector, "LOG_ROOT", logs):
            self.collector.prepare_rotation(ledger, deadline=time.monotonic() + 2)
            log.rename(logs / "usage.log.1")
            log.touch()
            self.collector.finish_rotation(ledger)
        self.refresh_fixture(ledger, logs, [account], end)
        segment = self.snapshot_segment(ledger, start, end)
        self.assertTrue(segment["complete"])
        self.assertEqual(segment["bytes"], 120)

    def test_managed_rotation_does_not_reuse_an_old_inode_cursor(self):
        ledger, logs, account = self.node_fixture()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        log = logs / "usage.log"
        log.write_text(f"v1 node 42 {self.collector.epoch_us(start)} 120\n")
        self.refresh_fixture(ledger, logs, [account], start)
        with patch.object(self.collector, "LOG_ROOT", logs):
            self.collector.prepare_rotation(ledger, deadline=time.monotonic() + 2)
            log.rename(logs / "usage.log.1")
            log.touch()
            info = log.stat()
            # A newly created current file may reuse an older deleted rotation's inode.
            with ledger.connection:
                ledger.connection.execute("INSERT INTO files VALUES (?,?,?,?)", (info.st_dev, info.st_ino, 999, b"old"))
            self.collector.finish_rotation(ledger)
        self.refresh_fixture(ledger, logs, [account], end)
        self.assertTrue(self.snapshot_segment(ledger, start, end)["complete"])

    def test_pressure_discards_are_explicit_and_fit_the_combined_budget(self):
        ledger, logs, _account = self.node_fixture()
        log = logs / "usage.log"
        log.write_bytes(b"x" * (256 * 1024))
        now = self.collector.utc_now()
        with (
            patch.object(self.collector, "LOG_ROOT", logs),
            patch.object(self.collector, "MAX_TELEMETRY_BYTES", 128 * 1024),
        ):
            self.collector.enforce_retention(ledger, deadline=time.monotonic() + 2, now=now)
            self.assertLessEqual(self.collector.telemetry_size(ledger), 128 * 1024)
        self.assertEqual(log.stat().st_size, 0)
        self.assertFalse(ledger.complete)
        self.assertGreaterEqual(self.collector.epoch_us(ledger.value("coverage_start")), self.collector.epoch_us(now))

    def test_interrupted_pressure_discard_cannot_restore_false_coverage(self):
        ledger, logs, _account = self.node_fixture()
        log = logs / "usage.log"
        log.write_text("v1 node 42 100 120\n")
        with patch.object(self.collector.os, "ftruncate", side_effect=OSError("fixture")), self.assertRaises(OSError):
            self.collector.discard_current_for_pressure(ledger, log)
        self.assertEqual(ledger.value("pending_pressure_loss"), "1")
        now = self.collector.utc_now()
        with patch.object(self.collector, "LOG_ROOT", logs):
            self.collector.enforce_retention(ledger, deadline=time.monotonic() + 2, now=now)
        self.assertIsNone(ledger.value("pending_pressure_loss"))
        self.assertGreaterEqual(self.collector.epoch_us(ledger.value("coverage_start")), self.collector.epoch_us(now))

    def test_query_budgets_do_not_turn_partial_totals_into_exact_values(self):
        ledger, logs, account = self.node_fixture()
        start, end = "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"
        epoch = self.collector.epoch_us(start)
        (logs / "usage.log").write_text(f"v1 node 42 {epoch} 100\nv1 node 42 {epoch + 1} 200\n")
        self.refresh_fixture(ledger, logs, [account], start)
        self.refresh_fixture(ledger, logs, [account], end)
        with patch.object(self.collector, "MAX_QUERY_ROWS", 1):
            with self.assertRaises(TimeoutError):
                ledger.total("node", "42", epoch, self.collector.epoch_us(end))
            self.assertFalse(self.snapshot_segment(ledger, start, end)["complete"])

    def test_metadata_output_bound_is_applied_before_buffering_the_whole_child(self):
        native = self.collector.subprocess.Popen
        processes = []

        def launch(_args, **kwargs):
            process = native([sys.executable, "-c", "import sys,time; sys.stdout.write('x'*64); sys.stdout.flush(); time.sleep(60)"], **kwargs)
            processes.append(process)
            return process

        with (
            patch.object(self.collector.subprocess, "Popen", side_effect=launch),
            patch.object(self.collector, "MAX_SNAPSHOT_BYTES", 32),
            self.assertRaises(ValueError),
        ):
            self.collector.read_metadata(deadline=time.monotonic() + 5)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())

    def test_metadata_timeout_reaps_the_child(self):
        native = self.collector.subprocess.Popen
        processes = []

        def launch(_args, **kwargs):
            process = native([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
            processes.append(process)
            return process

        with patch.object(self.collector.subprocess, "Popen", side_effect=launch), self.assertRaises(TimeoutError):
            self.collector.read_metadata(deadline=time.monotonic() + 0.1)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())

    def test_epoch_month_boundaries_and_owner_windows(self):
        ledger = self.collector.Ledger(Path(self.directory) / "usage.sqlite3")
        self.addCleanup(ledger.close)
        # 2026-10-31 22:00 UTC is midnight in Bucharest.
        boundary = 1793484000000000
        log = Path(self.directory) / "traffic.log"
        log.write_text(f"v1 node 42 {boundary - 1} 100\nv1 node 42 {boundary} 200\n")
        ledger.ingest(log)
        self.assertEqual(ledger.total("node", "42", boundary, boundary + 1), 200)
        self.assertEqual(ledger.total("node", "42", boundary - 1, boundary), 100)
        ledger.ingest(log)
        self.assertEqual(ledger.total("node", "42", 0, boundary + 1), 300)

    def test_partial_line_is_not_consumed_until_complete(self):
        ledger = self.collector.Ledger(Path(self.directory) / "usage.sqlite3")
        self.addCleanup(ledger.close)
        log = Path(self.directory) / "traffic.log"
        log.write_text("v1 node 42 100 12")
        ledger.ingest(log)
        self.assertEqual(ledger.total("node", "42", 0, 200), 0)
        with log.open("a") as stream:
            stream.write("\n")
        ledger.ingest(log)
        self.assertEqual(ledger.total("node", "42", 0, 200), 12)

    def test_symlink_escape_and_hardlinks_do_not_inflate_usage(self):
        home = Path(self.directory) / "home"
        home.mkdir()
        payload = home / "payload"
        payload.write_bytes(b"a" * 8192)
        (home / "again").hardlink_to(payload)
        (home / "outside").symlink_to("/etc")
        measured = self.collector.allocated_bytes(home)
        self.assertGreaterEqual(measured, payload.stat().st_blocks * 512)
        self.assertLess(measured, 32768)

    def test_truncation_invalidates_coverage(self):
        ledger = self.collector.Ledger(Path(self.directory) / "usage.sqlite3")
        self.addCleanup(ledger.close)
        log = Path(self.directory) / "traffic.log"
        log.write_text("v1 node 42 100 120\n")
        ledger.ingest(log)
        log.write_text("")
        ledger.ingest(log)
        self.assertFalse(ledger.complete)

    def test_rename_rotation_does_not_count_old_bytes_again(self):
        ledger = self.collector.Ledger(Path(self.directory) / "usage.sqlite3")
        self.addCleanup(ledger.close)
        log = Path(self.directory) / "traffic.log"
        log.write_text("v1 node 42 100 120\n")
        ledger.ingest(log)
        rotated = log.rename(log.with_suffix(".old"))
        log.write_text("v1 node 42 101 30\n")
        ledger.ingest(rotated)
        ledger.ingest(log)
        self.assertEqual(ledger.total("node", "42", 0, 200), 150)

    def test_failure_rolls_back_offsets_and_traffic_together(self):
        ledger = self.collector.Ledger(Path(self.directory) / "usage.sqlite3")
        self.addCleanup(ledger.close)
        log = Path(self.directory) / "traffic.log"
        log.write_text("v1 node 42 100 120\n" + "a" * 300)
        with self.assertRaises(ValueError):
            ledger.ingest(log)
        self.assertEqual(ledger.total("node", "42", 0, 200), 0)
        log.write_text("v1 node 42 100 120\n")
        ledger.ingest(log)
        self.assertEqual(ledger.total("node", "42", 0, 200), 120)

    def test_budgeted_ingestion_makes_progress_without_losing_remainder(self):
        ledger = self.collector.Ledger(Path(self.directory) / "usage.sqlite3")
        self.addCleanup(ledger.close)
        log = Path(self.directory) / "traffic.log"
        log.write_text("v1 node 42 100 120\nv1 node 42 101 30\n")
        with patch.object(self.collector, "MAX_REPLAY_BYTES", 20):
            ledger.ingest(log)
        self.assertEqual(ledger.total("node", "42", 0, 200), 120)
        ledger.ingest(log)
        self.assertEqual(ledger.total("node", "42", 0, 200), 150)

    def test_homes_cannot_be_symlinks(self):
        link = Path(self.directory) / "home"
        link.symlink_to("/etc")
        with self.assertRaises(OSError):
            self.collector.allocated_bytes(link)

    def test_operator_month_uses_bucharest_midnight_across_dst(self):
        start, end = self.collector.operator_month(datetime(2026, 10, 28, tzinfo=UTC), "Europe/Bucharest")
        self.assertEqual(start, datetime(2026, 9, 30, 21, tzinfo=UTC))
        self.assertEqual(end, datetime(2026, 10, 31, 22, tzinfo=UTC))
        with self.assertRaises(ValueError):
            self.collector.operator_month(datetime(2026, 10, 28), "Europe/Bucharest")

    def test_rewritten_prefix_is_not_counted_twice(self):
        ledger = self.collector.Ledger(Path(self.directory) / "usage.sqlite3")
        self.addCleanup(ledger.close)
        log = Path(self.directory) / "traffic.log"
        log.write_text("v1 node 42 100 120\n")
        ledger.ingest(log)
        log.write_text("v1 node 42 100 140\nv1 node 42 101 30\n")
        ledger.ingest(log)
        self.assertFalse(ledger.complete)
        self.assertEqual(ledger.total("node", "42", 0, 200), 120)

    def test_database_sizes_are_added_once_and_overlap_is_refused(self):
        root = Path(self.directory)
        home = root / "home"
        home.mkdir()
        (home / "files").write_bytes(b"x" * 8192)
        database = root / "mysql"
        database.mkdir()
        reading = self.collector.disk_measurement(home, [(database, 20480), (database, 20480)])
        self.assertEqual(reading["disk_db_bytes"], 20480)
        self.assertEqual(reading["databases"], 1)
        self.assertEqual(reading["disk_total_bytes"], reading["disk_files_bytes"] + 20480)
        with self.assertRaises(ValueError):
            self.collector.disk_measurement(home, [(home / "files", 20480)])

    def test_bad_database_values_are_not_coerced_into_measurements(self):
        root = Path(self.directory)
        for value in (True, -1, "20", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.collector.disk_measurement(root, [(root.parent, value)])

    def test_concurrent_collectors_do_not_ingest_the_same_prefix_twice(self):
        database = Path(self.directory) / "usage.sqlite3"
        self.collector.Ledger(database).close()
        log = Path(self.directory) / "traffic.log"
        log.write_text("v1 node 42 100 120\n")
        ready, readers = Barrier(3), Barrier(2)
        connect = sqlite3.connect

        class CoordinatedConnection(sqlite3.Connection):
            def execute(self, sql, *args):
                cursor = super().execute(sql, *args)
                if sql.startswith("SELECT offset,tail"):
                    # BEGIN IMMEDIATE serializes this point after the fix.
                    with suppress(BrokenBarrierError):
                        readers.wait(timeout=0.25)
                return cursor

        def collect():
            ledger = self.collector.Ledger(database)
            try:
                ready.wait(timeout=5)
                ledger.ingest(log)
            finally:
                ledger.close()

        with (
            patch.object(self.collector.sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=CoordinatedConnection)),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            workers = [pool.submit(collect) for _ in range(2)]
            ready.wait(timeout=5)
            for worker in workers:
                worker.result(timeout=10)
        ledger = self.collector.Ledger(database)
        self.addCleanup(ledger.close)
        self.assertEqual(ledger.total("node", "42", 0, 200), 120)
