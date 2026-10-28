"""Virtualmin info is CLI text inside JSON; utilization must not be inferred from load."""

from django.test import SimpleTestCase

from apps.provisioning.virtualmin_gateway import VirtualminGateway


class ResourceSnapshotTests(SimpleTestCase):
    def test_info_text_normalizes_real_cpu_memory_and_disk_units(self) -> None:
        snapshot = VirtualminGateway.resource_snapshot({"output": (
            "cpu:\n    * 20\n    * 10\n    * 65\n    * 4\n    * 1\n"
            "mem:\n    * 1048576\n    * 262144\n    * 2097152\n    * 2097152\n"
            "disk_total: 10737418240\ndisk_free: 2147483648\nload:\n    * 9.0\n"
        )})
        self.assertEqual(snapshot.cpu_percent, 35)
        self.assertEqual(snapshot.memory_percent, 75)
        self.assertEqual(snapshot.disk_percent, 80)
        self.assertFalse(snapshot.details()["measurement_time_known"])

    def test_missing_metrics_and_invalid_denominators_remain_unknown(self) -> None:
        for output in ("load:\n    * 100\n", "mem:\n    * 0\n    * 0\n", "disk_total: 0\ndisk_free: 0\n"):
            with self.subTest(output=output):
                snapshot = VirtualminGateway.resource_snapshot({"output": output})
                self.assertIsNone(snapshot.cpu_percent)
                self.assertIsNone(snapshot.memory_percent)
                self.assertIsNone(snapshot.disk_percent)

    def test_nonfinite_out_of_range_values_are_not_healthy_zeroes(self) -> None:
        snapshot = VirtualminGateway.resource_snapshot({"output": (
            "cpu:\n    * 0\n    * 0\n    * nan\nmem:\n    * 100\n    * 200\n"
            "disk_total: 100\ndisk_free: -1\n"
        )})
        self.assertIsNone(snapshot.cpu_percent)
        self.assertIsNone(snapshot.memory_percent)
        self.assertIsNone(snapshot.disk_percent)

    def test_malformed_tail_invalidates_the_whole_cpu_field(self) -> None:
        snapshot = VirtualminGateway.resource_snapshot({"output": "cpu:\n    * 10\n    * 20\n    * 70\n    * broken\n"})
        self.assertIsNone(snapshot.cpu_percent)
