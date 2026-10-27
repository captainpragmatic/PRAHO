"""Mail DNS plans preserve existing policy and bind exactly to complete caller observations."""

import base64
from dataclasses import replace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase

from apps.provisioning.virtualmin_mail_dns import (
    MailDnsRecord,
    MailDnsSnapshot,
    build_mail_dns_plan,
    check_mail_dns_plan,
    mail_dns_snapshot_digest,
)
from apps.provisioning.virtualmin_mail_service import MailDkimObservation

DOMAIN = "mail-plan.example.test"
ACCOUNT_NAME = "mail1234.accounts.example.test"
SPF_INCLUDE = "_spf.accounts.example.test"
OWNED_DKIM = "praho:hosted-zone-record:63cd73a9-0173-49db-a3a9-d70a7b076e34"


class MailDnsPlanTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        encoded = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.dkim = MailDkimObservation(
            "praho", f"praho._domainkey.{DOMAIN}", "v=DKIM1; k=rsa; p=" + base64.b64encode(encoded).decode()
        )

    def setUp(self):
        # This is a pure planner. Neither observation nor provider preparation may be invoked.
        for boundary in (
            "apps.infrastructure.dns_zone_gateway.get_zone_gateway",
            "apps.infrastructure.ansible_service.AnsibleService.run_playbook",
            "dns.resolver.Resolver.resolve",
            "dns.query.tcp",
            "dns.query.udp",
        ):
            self.enterContext(patch(boundary, side_effect=AssertionError("DNS planning must remain pure")))

    def record(self, kind, rdata, *, name=DOMAIN, ttl=600, owner_tag=""):
        return MailDnsRecord(name, kind, ttl, rdata, owner_tag)

    def snapshot(self, *records, revision=7, scope="zone", covered_rrsets=()):
        return MailDnsSnapshot(
            DOMAIN,
            revision,
            mail_dns_snapshot_digest(DOMAIN, revision, tuple(records), scope=scope, covered_rrsets=covered_rrsets),
            tuple(records),
            scope,
            covered_rrsets,
        )

    def plan(self, snapshot, **kwargs):
        return build_mail_dns_plan(
            snapshot,
            domain=DOMAIN,
            account_hostname=ACCOUNT_NAME,
            spf_include=SPF_INCLUDE,
            dkim=kwargs.pop("dkim", self.dkim),
            **kwargs,
        )

    def change(self, plan, slot):
        return next(change for change in plan.changes if change.slot == slot)

    def test_exact_before_after_merges_one_spf_and_preserves_external_sender_and_dmarc(self):
        external = self.record("MX", "20 external-mx.example.test.")
        spf = self.record("TXT", '"v=spf1 ip4:192.0.2.0/24 include:external.example.test -all"')
        unrelated = self.record("TXT", '"verification=unchanged" " octets"')
        dmarc = self.record("TXT", '"v=DMARC1; p=reject; rua=mailto:report@example.test"', name=f"_dmarc.{DOMAIN}")
        snapshot = self.snapshot(external, spf, unrelated, dmarc)
        plan = self.plan(snapshot).unwrap()
        mx = self.change(plan, "mx")
        self.assertEqual(mx.before, (external,))
        self.assertEqual(mx.after[0].rdata, f"10 {ACCOUNT_NAME}.")
        merged = self.change(plan, "spf").after[0]
        self.assertIn(f"include:external.example.test include:{SPF_INCLUDE} -all", merged.rdata)
        self.assertIn("ip4:192.0.2.0/24", merged.rdata)
        self.assertIn(unrelated, plan.observed_after_records)
        self.assertIn(dmarc, plan.observed_after_records)
        public = plan.to_consent()
        self.assertEqual(
            public["source"],
            {
                "zone_name": DOMAIN,
                "revision": snapshot.revision,
                "digest": snapshot.digest,
                "scope": "zone",
                "covered_rrsets": [],
            },
        )
        self.assertNotIn("owner_tag", str(public))
        self.assertEqual(public["checks"]["recursive_spf_lookups"], "unverified")
        self.assertEqual(public["checks"]["negative_ttl"], "unverified")
        self.assertNotIn("dns_ready", public)
        self.assertEqual(mx.after[0].ttl, 300)
        self.assertEqual(merged.ttl, 600)

    def test_no_previous_spf_uses_neutral_fallback_and_a_real_observed_public_key(self):
        plan = self.plan(self.snapshot()).unwrap()
        self.assertEqual(self.change(plan, "spf").after[0].rdata, f'"v=spf1 include:{SPF_INCLUDE} ?all"')
        self.assertEqual(self.change(plan, "dkim").after[0].name, self.dkim.record_name)
        self.assertIn("p=", self.change(plan, "dkim").after[0].rdata)
        self.assertNotIn("private", str(plan.to_consent()).lower())

    def test_existing_terminal_and_implicit_neutral_policies_keep_their_semantics(self):
        for suffix in ("?all", "~all", "-all", ""):
            with self.subTest(suffix=suffix):
                policy = f"v=spf1 include:external.example.test {suffix}".rstrip()
                plan = self.plan(self.snapshot(self.record("TXT", f'"{policy}"'))).unwrap()
                actual = self.change(plan, "spf").after[0].rdata
                expected = f"v=spf1 include:external.example.test include:{SPF_INCLUDE}"
                if suffix:
                    expected += " " + suffix
                self.assertEqual(actual, f'"{expected}"')

    def test_safe_redirect_preserves_fallback_after_our_positive_include(self):
        record = self.record("TXT", '"v=spf1 ip6:2001:db8::/32 redirect=_spf.external.example.test"')
        plan = self.plan(self.snapshot(record)).unwrap()
        self.assertEqual(
            self.change(plan, "spf").after[0].rdata,
            f'"v=spf1 ip6:2001:db8::/32 include:{SPF_INCLUDE} redirect=_spf.external.example.test"',
        )

    def test_txt_chunks_are_concatenated_without_adding_spaces_before_spf_parsing(self):
        record = self.record("TXT", '"v=spf1 include:external." "example.test -all"')
        plan = self.plan(self.snapshot(record)).unwrap()
        self.assertIn(
            f"include:external.example.test include:{SPF_INCLUDE} -all", self.change(plan, "spf").after[0].rdata
        )

    def test_multiple_spf_records_and_unsafe_all_redirect_or_include_combinations_refuse(self):
        spf = self.record("TXT", '"v=spf1 -all"')
        self.assertEqual(self.plan(self.snapshot(spf, spf)).unwrap_err(), "mail_spf_ambiguous")
        for value in (
            "v=spf1 +all",
            "v=spf1 all",
            "v=spf1 -all include:external.example.test",
            "v=spf1 -all redirect=external.example.test",
            "v=spf1 redirect=a.example.test redirect=b.example.test",
            f"v=spf1 -include:{SPF_INCLUDE} -all",
            "v=spf1 include:%{d} -all",
            f"v=spf1 redirect={DOMAIN}",
        ):
            with self.subTest(value=value):
                self.assertTrue(self.plan(self.snapshot(self.record("TXT", f'"{value}"'))).is_err())

    def test_local_lookup_budget_is_checked_without_claiming_recursive_validation(self):
        includes = " ".join(f"include:p{index}.example.test" for index in range(10))
        self.assertEqual(
            self.plan(self.snapshot(self.record("TXT", f'"v=spf1 {includes} -all"'))).unwrap_err(),
            "mail_spf_lookup_limit",
        )

    def test_apex_mx_dependency_refuses_to_silently_remove_existing_external_senders(self):
        for term in ("mx", f"mx:{DOMAIN}", f"mx:{DOMAIN}/24//64"):
            with self.subTest(term=term):
                snapshot = self.snapshot(
                    self.record("MX", "10 external.example.test."), self.record("TXT", f'"v=spf1 {term} -all"')
                )
                self.assertEqual(self.plan(snapshot).unwrap_err(), "mail_spf_mx_dependency")
        plan = self.plan(
            self.snapshot(
                self.record("MX", "10 external.example.test."),
                self.record("TXT", '"v=spf1 mx:external-domain.example.test -all"'),
            )
        ).unwrap()
        self.assertIn("mx:external-domain.example.test", self.change(plan, "spf").after[0].rdata)

    def test_missing_malformed_or_foreign_dkim_is_preparation_refusal(self):
        for dkim in (
            None,
            replace(self.dkim, record_value="v=DKIM1; k=rsa; p="),
            replace(self.dkim, record_name="praho._domainkey.foreign.example.test"),
        ):
            with self.subTest(missing=dkim is None):
                self.assertEqual(self.plan(self.snapshot(), dkim=dkim).unwrap_err(), "mail_dkim_preparation_required")

    def test_conflicting_unowned_or_delegated_dkim_cannot_be_overwritten(self):
        conflict = self.record("TXT", '"v=DKIM1; p=other"', name=self.dkim.record_name)
        self.assertEqual(self.plan(self.snapshot(conflict)).unwrap_err(), "mail_dkim_conflict")
        self.assertEqual(
            self.plan(
                self.snapshot(self.record("CNAME", "external-key.example.test.", name=self.dkim.record_name))
            ).unwrap_err(),
            "mail_dkim_conflict",
        )
        owned = replace(conflict, owner_tag=OWNED_DKIM)
        plan = self.plan(self.snapshot(owned), owned_dkim_tag=OWNED_DKIM).unwrap()
        self.assertEqual(self.change(plan, "dkim").before, (owned,))

    def test_revision_digest_content_and_ownership_drift_all_invalidate_publication_preflight(self):
        snapshot = self.snapshot(self.record("TXT", '"verification=old"'))
        plan = self.plan(snapshot).unwrap()
        self.assertTrue(check_mail_dns_plan(plan, snapshot).is_ok())
        for current in (
            replace(snapshot, revision=8),
            replace(snapshot, digest="f" * 64),
            self.snapshot(self.record("TXT", '"verification=new"')),
            self.snapshot(self.record("TXT", '"verification=old"', owner_tag=OWNED_DKIM)),
            replace(snapshot, scope="rrsets"),
        ):
            with self.subTest(revision=current.revision):
                self.assertTrue(check_mail_dns_plan(plan, current).is_err())
        self.assertTrue(self.plan(replace(snapshot, digest="0" * 64)).is_err())
        self.assertTrue(self.plan(replace(snapshot, scope="rrsets")).is_err())

    def test_planning_the_already_applied_manifest_is_a_noop_and_preserves_original_txt_chunks(self):
        first = self.plan(self.snapshot()).unwrap()
        snapshot = self.snapshot(*first.observed_after_records, revision=8)
        second = self.plan(snapshot).unwrap()
        self.assertEqual(second.changes, ())
        self.assertEqual(second.observed_after_records, snapshot.records)

    def rrset_coverage(self):
        return (
            (DOMAIN, "MX"),
            (DOMAIN, "TXT"),
            (DOMAIN, "CNAME"),
            (self.dkim.record_name, "TXT"),
            (self.dkim.record_name, "CNAME"),
        )

    def test_external_dns_uses_explicit_complete_rrsets_without_claiming_a_complete_zone(self):
        observed = self.record("TXT", '"external-verification=keep"')
        snapshot = self.snapshot(observed, scope="rrsets", covered_rrsets=self.rrset_coverage())
        plan = self.plan(snapshot).unwrap()
        self.assertEqual(plan.scope, "rrsets")
        self.assertIn(observed, plan.observed_after_records)
        self.assertEqual(plan.to_consent()["source"]["scope"], "rrsets")
        self.assertNotIn(f"_dmarc.{DOMAIN}", str(plan.to_consent()["changes"]))
        self.assertTrue(check_mail_dns_plan(plan, snapshot).is_ok())

    def test_proved_empty_rrsets_are_different_from_unobserved_sets(self):
        coverage = self.rrset_coverage()
        self.assertTrue(self.plan(self.snapshot(scope="rrsets", covered_rrsets=coverage)).is_ok())
        for missing in coverage:
            with self.subTest(missing=missing):
                incomplete = self.snapshot(
                    scope="rrsets", covered_rrsets=tuple(key for key in coverage if key != missing)
                )
                self.assertEqual(self.plan(incomplete).unwrap_err(), "mail_dns_observation_incomplete")

    def test_external_rrsets_can_be_observed_under_a_parent_authority_without_a_delegated_customer_zone(self):
        coverage = self.rrset_coverage()
        parent = "example.test"
        snapshot = MailDnsSnapshot(
            parent,
            1,
            mail_dns_snapshot_digest(parent, 1, (), scope="rrsets", covered_rrsets=coverage),
            (),
            "rrsets",
            coverage,
        )
        plan = self.plan(snapshot).unwrap()
        self.assertEqual(plan.zone_name, parent)
        self.assertTrue(
            all(
                change.after[0].name == DOMAIN or change.after[0].name == self.dkim.record_name
                for change in plan.changes
            )
        )

    def test_full_parent_inventory_can_plan_only_the_contained_child_mail_records(self):
        parent = "example.test"
        parent_verification = self.record("TXT", '"parent-verification=keep"', name=parent)
        sibling = self.record("MX", "10 other-provider.example.test.", name="sibling.example.test")
        parent_dmarc = self.record("TXT", '"v=DMARC1; p=reject"', name="_dmarc.example.test")
        records = (parent_verification, sibling, parent_dmarc)
        snapshot = MailDnsSnapshot(parent, 9, mail_dns_snapshot_digest(parent, 9, records), records)
        plan = self.plan(snapshot).unwrap()
        self.assertEqual(plan.scope, "zone")
        self.assertEqual(plan.zone_name, parent)
        self.assertTrue(check_mail_dns_plan(plan, snapshot).is_ok())
        self.assertTrue(all(row in plan.observed_after_records for row in records))
        self.assertEqual(
            {row.name for change in plan.changes for row in (*change.before, *change.after)},
            {DOMAIN, self.dkim.record_name},
        )

    def test_containment_uses_dns_labels_and_still_refuses_foreign_zone_snapshots(self):
        for zone in ("unrelated.test", "ample.test", "example.test.evil"):
            with self.subTest(zone=zone):
                snapshot = MailDnsSnapshot(zone, 1, mail_dns_snapshot_digest(zone, 1, ()), ())
                self.assertTrue(self.plan(snapshot).is_err())

    def test_preflight_binds_the_plan_scope_and_coverage_fields_as_well_as_the_source_digest(self):
        snapshot = self.snapshot()
        plan = self.plan(snapshot).unwrap()
        for altered in (
            replace(plan, scope="rrsets", covered_rrsets=self.rrset_coverage()),
            replace(plan, covered_rrsets=((DOMAIN, "TXT"),)),
        ):
            with self.subTest(scope=altered.scope):
                self.assertEqual(check_mail_dns_plan(altered, snapshot).unwrap_err(), "mail_dns_snapshot_stale")
        rrsets = self.snapshot(scope="rrsets", covered_rrsets=self.rrset_coverage())
        narrow = self.plan(rrsets).unwrap()
        self.assertEqual(check_mail_dns_plan(narrow, snapshot).unwrap_err(), "mail_dns_snapshot_stale")

    def test_adding_mail_records_cannot_exceed_the_complete_manifest_limit(self):
        records = tuple(self.record("A", "192.0.2.10", name=f"unrelated-{index}.{DOMAIN}") for index in range(2000))
        self.assertEqual(self.plan(self.snapshot(*records)).unwrap_err(), "mail_dns_snapshot_invalid")

    def test_proxy_enabled_selector_metadata_cannot_be_treated_as_publishable_dkim(self):
        existing = self.change(self.plan(self.snapshot()).unwrap(), "dkim").after[0]
        with self.assertRaises(ValueError):
            self.snapshot(replace(existing, proxied=True))
        invalid = replace(self.snapshot(existing), records=(replace(existing, proxied=True),))
        self.assertEqual(self.plan(invalid).unwrap_err(), "mail_dns_snapshot_invalid")

    def test_record_bounds_include_owner_and_header_not_only_rdata(self):
        large = self.record("TXT", " ".join('"' + "x" * 253 + '"' for _ in range(16)))
        with self.assertRaises(ValueError):
            mail_dns_snapshot_digest(DOMAIN, 1, (large,))
