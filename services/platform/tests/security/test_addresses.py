"""Address bounds preserve exact dual-stack containment in database comparisons."""

from django.test import SimpleTestCase

from apps.security.addresses import address_bounds, pack_address


class SecurityAddressTests(SimpleTestCase):
    def test_fixed_width_packing_and_cidr_bounds(self) -> None:
        for scope, value, first, last, family in (
            ("range", "198.51.100.8/30", "198.51.100.8", "198.51.100.11", 4),
            ("range", "2001:db8::8/126", "2001:db8::8", "2001:db8::b", 6),
            ("ip", "192.0.2.1", "192.0.2.1", "192.0.2.1", 4),
        ):
            with self.subTest(value=value):
                bounds = address_bounds(scope, value)
                self.assertEqual(bounds.address_family, family)
                self.assertEqual(bounds.network_start, pack_address(first)[1])
                self.assertEqual(bounds.network_end, pack_address(last)[1])
                self.assertEqual(len(bounds.network_start), 16)
                self.assertEqual(len(bounds.network_end), 16)
        self.assertEqual(pack_address("192.0.2.1"), (4, bytes.fromhex("000000000000000000000000c0000201")))
        with self.assertRaises(ValueError):
            address_bounds("range", "198.51.100.9/30")

    def test_mapped_ipv4_hosts_use_the_same_family_and_bytes_as_the_enforcing_bouncer(self) -> None:
        self.assertEqual(pack_address("::ffff:192.0.2.1"), pack_address("192.0.2.1"))
