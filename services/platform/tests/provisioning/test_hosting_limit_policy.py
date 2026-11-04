"""Exact policy boundaries, separate from native capability and observation."""

from django.test import SimpleTestCase

from apps.provisioning.hosting_limit_policy import Allowance, effective_disk_limit, resolve_allowance


class HostingLimitPolicyTests(SimpleTestCase):
    def test_catalog_default_and_unlimited_provenance(self) -> None:
        for plan, default, expected in (
            (5, 97, Allowance(5120, "plan")),
            (0, 97, Allowance(0, "plan")),
            (None, 37, Allowance(37, "stored_default")),
            (None, 0, Allowance(0, "stored_default")),
            (None, None, Allowance(0, "unlimited")),
        ):
            with self.subTest(plan=plan, default=default):
                self.assertEqual(resolve_allowance(plan, default), expected)

    def test_invalid_quantities_never_become_finite_or_unlimited(self) -> None:
        for value in (True, False, -1, 1.5, "5"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    resolve_allowance(value, None)
                with self.assertRaises(ValueError):
                    resolve_allowance(None, value)
                with self.assertRaises(ValueError):
                    effective_disk_limit(value)

    def test_margin_is_integer_ceil_and_capped_at_two_gib(self) -> None:
        for allowance, effective in (
            (None, None),
            (0, 0),
            (1, 2),
            (9, 10),
            (10, 11),
            (11, 13),
            (5120, 5632),
            (20479, 22527),
            (20480, 22528),
            (20481, 22529),
            (40960, 43008),
        ):
            with self.subTest(allowance=allowance):
                self.assertEqual(effective_disk_limit(allowance), effective)

    def test_raise_is_fixed_and_bounded_above_headroom(self) -> None:
        self.assertEqual(effective_disk_limit(5120, extra_mib=1280), 6912)
        self.assertEqual(effective_disk_limit(40960, extra_mib=5120), 48128)
        for allowance, extra in ((5120, 1281), (40960, 5121), (0, 1), (None, 1), (5, True), (5, -1)):
            with self.subTest(allowance=allowance, extra=extra), self.assertRaises(ValueError):
                effective_disk_limit(allowance, extra_mib=extra)
