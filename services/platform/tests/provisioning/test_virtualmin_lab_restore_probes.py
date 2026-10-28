"""The live restore observer distinguishes held websites from the neutral default site."""

import io

from django.core.management.base import CommandError
from django.test import SimpleTestCase

from apps.provisioning.management.commands.virtualmin_lab_checks import CHECK_DOMAIN, MIN_PROBES, Command


class PairRestoreProbeTests(SimpleTestCase):
    def setUp(self):
        self.command = Command(stdout=io.StringIO())
        self.responses = [
            (CHECK_DOMAIN, "503", "503"),
            (CHECK_DOMAIN.upper(), "503", "503"),
            (CHECK_DOMAIN + ".", "503", "503"),
            ("www." + CHECK_DOMAIN, "503", "503"),
            ("mail." + CHECK_DOMAIN, "503", "503"),
            ("webmail." + CHECK_DOMAIN, "503", "503"),
            ("admin." + CHECK_DOMAIN, "503", "503"),
            ("unknown.invalid", "404", "404"),
            ("IP-LITERAL", "404", "404"),
        ]
        self.expected_hosts = {host for host, _, _ in self.responses}
        self.rows = [(float(index), *response) for index, response in enumerate(self.responses * 3)]

    def test_held_domains_and_neutral_defaults_are_both_checked(self):
        self.command._check_pair_restore_probes(self.rows, self.expected_hosts)

    def test_every_named_host_must_stay_held_on_each_port(self):
        self.command._check_pair_restore_probes(self.rows, self.expected_hosts)
        for host, _, _ in self.responses[:7]:
            for codes in (("200", "503"), ("503", "200"), ("404", "404"), ("301", "503"), ("503", "000")):
                with self.subTest(host=host, codes=codes), self.assertRaises(CommandError):
                    rows = [
                        (at, name, *codes) if name == host else (at, name, http, https)
                        for at, name, http, https in self.rows
                    ]
                    self.command._check_pair_restore_probes(rows, self.expected_hosts)

    def test_unclaimed_hosts_must_retain_the_neutral_response_on_each_port(self):
        self.command._check_pair_restore_probes(self.rows, self.expected_hosts)
        for host in ("unknown.invalid", "IP-LITERAL"):
            for codes in (("503", "503"), ("200", "404"), ("404", "200"), ("404", "302"), ("000", "404")):
                with self.subTest(host=host, codes=codes), self.assertRaises(CommandError):
                    rows = [
                        (at, name, *codes) if name == host else (at, name, http, https)
                        for at, name, http, https in self.rows
                    ]
                    self.command._check_pair_restore_probes(rows, self.expected_hosts)

    def test_missing_observations_for_any_host_fail_even_with_enough_total_rows(self):
        self.command._check_pair_restore_probes(self.rows, self.expected_hosts)
        for host in self.expected_hosts:
            with self.subTest(host=host), self.assertRaises(CommandError):
                rows = [row for row in self.rows if row[1] != host]
                self.assertGreaterEqual(len(rows), MIN_PROBES)
                self.command._check_pair_restore_probes(rows, self.expected_hosts)

    def test_observation_count_boundary_does_not_relax_host_coverage(self):
        self.command._check_pair_restore_probes(self.rows, self.expected_hosts)
        for count in (MIN_PROBES - 1, MIN_PROBES, MIN_PROBES + 1):
            with self.subTest(count=count):
                rows = self.rows[:count]
                self.assertEqual({row[1] for row in rows}, self.expected_hosts)
                if count < MIN_PROBES:
                    with self.assertRaises(CommandError):
                        self.command._check_pair_restore_probes(rows, self.expected_hosts)
                else:
                    self.command._check_pair_restore_probes(rows, self.expected_hosts)
