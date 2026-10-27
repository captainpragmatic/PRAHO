"""Cloudflare customer-zone contracts use only a scripted HTTP boundary, never live credentials."""

from collections import defaultdict, deque
from dataclasses import replace
from unittest.mock import patch

import requests
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from apps.common.types import Retriability, retriability_of
from apps.infrastructure.dns_zone_cloudflare import CloudflareZoneGateway
from apps.infrastructure.dns_zone_gateway import ZoneBinding, ZoneRecordSpec, get_zone_gateway, validate_record_spec
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_admin_user, create_staff_user
from tests.infrastructure.test_dns_gateway_cloudflare import CLOUDFLARE_API_BASE, FakeResponse

ACCOUNT = "a" * 32
ZONE = "b" * 32
NAME = "customer.example.net"
LOCAL = "00000000-0000-4000-8000-000000000001"
OWNER = f"praho:hosted-zone-record:{LOCAL}"
BINDING = ZoneBinding("cloudflare", ACCOUNT, ZONE, NAME)
HTTP = "apps.infrastructure.dns_gateway.safe_request"
TOKEN_KEY = "dns.cloudflare_account_api_token"


class Cloudflare:
    def __init__(self):
        self.calls = []
        self.zones_exist = True
        self.records = {}
        self.scripted = defaultdict(deque)
        self.size = 2
        self.identity = {
            "id": ZONE,
            "name": NAME,
            "account": {"id": ACCOUNT},
            "type": "full",
            "status": "pending",
            "name_servers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
            "plan": {"name": "Free Website"},
        }

    def __call__(self, method, url, *, policy, headers, **kwargs):  # noqa: C901, PLR0911, PLR0912  # Scripted HTTP endpoint router.
        path = url.removeprefix(CLOUDFLARE_API_BASE)
        self.calls.append((method, path, kwargs, policy, headers))
        if self.scripted[(method, path)]:
            response = self.scripted[(method, path)].popleft()
            if isinstance(response, Exception):
                raise response
            return response
        if path == "/zones" and method == "GET":
            return self.listing([self.identity] if self.zones_exist else [], kwargs.get("params", {}))
        if path == "/zones" and method == "POST":
            self.zones_exist = True
            return self.ok(self.identity)
        if path == f"/zones/{ZONE}":
            if not self.zones_exist:
                return FakeResponse(404, {"success": False})
            if method == "DELETE":
                self.zones_exist = False
            return self.ok({"id": ZONE} if method == "DELETE" else self.identity)
        if path == f"/zones/{ZONE}/activation_check":
            return self.ok({"id": ZONE})
        if path == f"/zones/{ZONE}/dnssec":
            return self.ok({"status": "disabled", "ds": ""})
        collection = f"/zones/{ZONE}/dns_records"
        if path == collection and method == "GET":
            return self.listing(list(self.records.values()), kwargs.get("params", {}))
        if path == collection and method == "POST":
            record_id = f"{len(self.records) + 1:032x}"
            self.records[record_id] = {"id": record_id, **kwargs["json"]}
            return self.ok(self.records[record_id])
        record_id = path.removeprefix(f"{collection}/")
        if record_id in self.records:
            if method == "GET":
                return self.ok(self.records[record_id])
            if method == "PUT":
                self.records[record_id] = {"id": record_id, **kwargs["json"]}
                return self.ok(self.records[record_id])
            if method == "DELETE":
                self.records.pop(record_id)
                return self.ok({"id": record_id})
        return FakeResponse(404, {"success": False, "errors": []})

    @staticmethod
    def ok(value):
        return FakeResponse(200, {"success": True, "result": value})

    def listing(self, values, params):
        page = params.get("page", 1)
        batch = values[(page - 1) * self.size : page * self.size]
        return FakeResponse(
            200,
            {
                "success": True,
                "result": batch,
                "result_info": {
                    "page": page,
                    "per_page": self.size,
                    "count": len(batch),
                    "total_count": len(values),
                    "total_pages": max(1, (len(values) + self.size - 1) // self.size),
                },
            },
        )

    def seed(self, number=1, **overrides):
        record_id = f"{number:032x}"
        self.records[record_id] = {
            "id": record_id,
            "type": "A",
            "name": NAME,
            "content": "95.217.0.20",
            "ttl": 300,
            "proxied": False,
            "comment": OWNER,
            **overrides,
        }
        return record_id


def spec(kind="A", rdata="95.217.0.20", **kwargs):
    return ZoneRecordSpec(LOCAL, NAME, kind, 300, rdata, OWNER, **kwargs)


class ZoneGatewayTests(SimpleTestCase):
    def setUp(self):
        self.http = Cloudflare()
        self.enterContext(patch(HTTP, self.http))
        self.gateway = CloudflareZoneGateway(token="customer-zone-token", account_id=ACCOUNT, max_retries=0)

    def test_create_zone_requires_prior_absence_and_does_not_adopt_an_existing_zone(self):
        self.assertTrue(self.gateway.create_zone(ACCOUNT, NAME).is_err())
        self.assertFalse(any(method == "POST" for method, *_ in self.http.calls))
        self.http.zones_exist = False
        result = self.gateway.create_zone(ACCOUNT, NAME)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap().binding, BINDING)
        self.assertEqual(result.unwrap().plan, "free")
        call = next(call for call in self.http.calls if call[0] == "POST")
        self.assertEqual(call[2]["json"], {"account": {"id": ACCOUNT}, "name": NAME, "type": "full"})

    def test_a_full_zone_requires_at_least_two_distinct_assigned_nameservers(self):
        for nameservers in (
            ["ns1.cloudflare.com"],
            ["ns1.cloudflare.com", "ns1.cloudflare.com"],
            ["ns1.cloudflare.com", "NS1.CLOUDFLARE.COM."],
        ):
            with self.subTest(nameservers=nameservers):
                self.http.identity["name_servers"] = nameservers
                self.assertTrue(self.gateway.read_zone(BINDING).is_err())

    def test_a_wrong_account_or_name_or_provider_binding_refuses_before_record_mutation(self):
        for binding in (
            replace(BINDING, provider="other"),
            replace(BINDING, account_id="c" * 32),
            replace(BINDING, name="other.example.net"),
        ):
            with self.subTest(binding=binding):
                self.assertTrue(self.gateway.create_record(binding, spec()).is_err())
        self.assertFalse(any(method == "POST" for method, *_ in self.http.calls))

    def test_the_token_and_safe_https_transport_are_separate_from_node_credentials(self):
        self.assertTrue(self.gateway.read_zone(BINDING).is_ok())
        method, path, _, policy, headers = self.http.calls[-1]
        self.assertEqual((method, path), ("GET", f"/zones/{ZONE}"))
        self.assertEqual(headers["Authorization"], "Bearer customer-zone-token")
        self.assertTrue(policy.require_https)
        self.assertEqual(policy.allowed_domains, frozenset({"api.cloudflare.com"}))
        self.assertFalse(policy.retry_connection_errors)
        self.assertEqual(policy.max_retries, 0)

    def test_zone_activation_is_put_and_dnssec_is_read_only(self):
        self.assertTrue(self.gateway.trigger_activation(BINDING).is_ok())
        self.assertTrue(self.gateway.get_dnssec(BINDING).is_ok())
        self.assertIn(
            ("PUT", f"/zones/{ZONE}/activation_check"), [(method, path) for method, path, *_ in self.http.calls]
        )
        self.assertEqual(self.gateway.get_dnssec(BINDING).unwrap().status, "disabled")

    def test_all_seven_families_have_typed_payloads_and_round_trip_canonical_rdata(self):
        cases = (
            ("A", "95.217.0.20", {"content": "95.217.0.20"}),
            ("AAAA", "2a01:4f9:c010::20", {"content": "2a01:4f9:c010::20"}),
            ("CNAME", "a123.accounts.example.net.", {"content": "a123.accounts.example.net"}),
            ("MX", "10 mail.external.example.", {"content": "mail.external.example", "priority": 10}),
            (
                "TXT",
                '"v=spf1 " "include:external.example -all"',
                {"content": '"v=spf1 " "include:external.example -all"'},
            ),
            (
                "SRV",
                "10 20 443 service.external.example.",
                {"data": {"priority": 10, "weight": 20, "port": 443, "target": "service.external.example"}},
            ),
            ("CAA", '0 issue "letsencrypt.org"', {"data": {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}}),
        )
        for kind, rdata, payload in cases:
            with self.subTest(type=kind):
                name = f"_service._tcp.{NAME}" if kind == "SRV" else f"www.{NAME}" if kind == "CNAME" else NAME
                result = self.gateway.create_record(BINDING, replace(spec(kind, rdata), name=name))
                self.assertTrue(result.is_ok(), result)
                self.assertEqual(result.unwrap().spec.rdata, rdata)
                sent = [call[2]["json"] for call in self.http.calls if call[0] == "POST"][-1]
                for key, value in payload.items():
                    self.assertEqual(sent[key], value)

    def test_invalid_record_payloads_refuse_before_provider_writes(self):
        for bad in (
            replace(spec(), ttl=30),
            replace(spec(), ttl=True),
            replace(spec(), proxied=True),
            replace(spec(), name="other.example.org"),
            replace(spec(), rdata="not-an-address"),
            replace(spec("CNAME", "target.example.net."), name=NAME),
            spec("MX", "65536 mail.example.net."),
            spec("CAA", '0 unknown "value"'),
            replace(spec(), owner_tag="other-owner"),
        ):
            with self.subTest(spec=bad):
                self.assertTrue(self.gateway.create_record(BINDING, bad).is_err())
        self.assertFalse(any(method == "POST" for method, *_ in self.http.calls))

    def test_record_update_and_delete_require_fresh_exact_ownership(self):
        record_id = self.http.seed(comment="foreign-owner")
        self.assertTrue(self.gateway.update_record(BINDING, record_id, spec()).is_err())
        self.assertTrue(self.gateway.delete_record(BINDING, record_id, expected_owner_tag=OWNER).is_err())
        self.assertFalse(any(method in {"PUT", "DELETE"} for method, *_ in self.http.calls))
        self.http.records[record_id]["comment"] = OWNER
        self.assertTrue(self.gateway.update_record(BINDING, record_id, replace(spec(), ttl=60)).is_ok())
        self.assertEqual(self.http.records[record_id]["ttl"], 60)
        self.assertTrue(self.gateway.delete_record(BINDING, record_id, expected_owner_tag=OWNER).is_ok())

    def test_full_record_listing_preserves_unowned_records_and_follows_every_page(self):
        for number in range(1, 4):
            self.http.seed(number, comment=OWNER if number == 1 else "")
        result = self.gateway.list_records(BINDING)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(len(result.unwrap().records), 3)
        self.assertEqual(result.unwrap().records[1].spec.owner_tag, "")
        pages = [
            kwargs["params"]["page"] for method, path, kwargs, *_ in self.http.calls if path.endswith("/dns_records")
        ]
        self.assertEqual(pages, [1, 2])

    def test_incomplete_metadata_duplicate_ids_and_count_drift_never_return_partial_inventory(self):
        self.http.seed()
        valid = self.http.listing(list(self.http.records.values()), {"page": 1}).json()
        variants = [
            {"success": True, "result": valid["result"]},
            {**valid, "result_info": {**valid["result_info"], "count": 0}},
            {**valid, "result_info": {**valid["result_info"], "page": 2}},
            {**valid, "result_info": {**valid["result_info"], "total_count": 3, "total_pages": 2}},
            {
                **valid,
                "result": valid["result"] * 2,
                "result_info": {**valid["result_info"], "count": 2, "total_count": 2},
            },
        ]
        for body in variants:
            with self.subTest(body=body):
                self.http.scripted[("GET", f"/zones/{ZONE}/dns_records")].append(FakeResponse(200, body))
                self.assertTrue(self.gateway.list_records(BINDING).is_err())

    def test_a_repeated_page_and_total_count_change_mid_listing_are_refused(self):
        for number in range(1, 4):
            self.http.seed(number)
        first = self.http.listing(list(self.http.records.values()), {"page": 1}).json()
        for second in (first, {**first, "result_info": {**first["result_info"], "page": 2, "total_count": 4}}):
            with self.subTest(second=second):
                self.http.scripted[("GET", f"/zones/{ZONE}/dns_records")].extend(
                    [FakeResponse(200, first), FakeResponse(200, second)]
                )
                self.assertTrue(self.gateway.list_records(BINDING).is_err())

    def test_unsupported_provider_record_is_an_explicit_refusal_not_a_dropped_inventory_entry(self):
        self.http.seed(type="TLSA", content="3 1 1 abcd")
        self.assertTrue(self.gateway.list_records(BINDING).is_err())

    def test_an_ambiguous_zone_create_or_record_create_is_unknown_and_never_replayed(self):
        self.http.zones_exist = False
        self.http.scripted[("POST", "/zones")].append(FakeResponse(503, {"success": False}))
        outcome = self.gateway.create_zone(ACCOUNT, NAME)
        self.assertEqual(retriability_of(outcome), Retriability.UNKNOWN)
        self.http.zones_exist = True
        self.http.scripted[("POST", f"/zones/{ZONE}/dns_records")].append(requests.Timeout("response lost"))
        outcome = self.gateway.create_record(BINDING, spec())
        self.assertEqual(retriability_of(outcome), Retriability.UNKNOWN)
        self.assertEqual(sum(method == "POST" for method, *_ in self.http.calls), 2)

    def test_a_put_that_landed_before_timeout_is_confirmed_by_fresh_bound_owned_readback(self):
        record_id = self.http.seed()
        original = self.http

        def lose_put_response(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "PUT":
                raise requests.Timeout("update response lost")
            return response

        with patch(HTTP, lose_put_response):
            outcome = self.gateway.update_record(BINDING, record_id, replace(spec(), ttl=60))
        self.assertTrue(outcome.is_ok(), outcome)
        self.assertEqual(outcome.unwrap().spec.ttl, 60)
        self.assertEqual(sum(method == "PUT" for method, *_ in self.http.calls), 1)
        self.assertEqual(sum(method == "GET" and path.endswith(record_id) for method, path, *_ in self.http.calls), 2)

    def test_ambiguous_put_never_replays_over_a_record_whose_owner_changed(self):
        record_id = self.http.seed()
        original = self.http

        def change_owner_after_put(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "PUT":
                self.http.records[record_id]["comment"] = "foreign-owner"
                return FakeResponse(503, {"success": False})
            return response

        gateway = CloudflareZoneGateway(token="customer-zone-token", account_id=ACCOUNT)
        with patch(HTTP, change_owner_after_put), patch("apps.infrastructure.dns_gateway.time.sleep"):
            outcome = gateway.update_record(BINDING, record_id, replace(spec(), ttl=60))
        self.assertTrue(outcome.is_err())
        self.assertEqual(sum(method == "PUT" for method, *_ in self.http.calls), 1)
        self.assertEqual(self.http.records[record_id]["comment"], "foreign-owner")

    def test_manifest_preflight_accounts_for_owner_and_rr_header_in_the_wire_limit(self):
        owner = ".".join(["x" * 63, "y" * 63, "z" * 63, "example", "net"])
        text = " ".join('"' + "a" * 250 + '"' for _ in range(16))
        outcome = validate_record_spec(replace(spec("TXT", text), name=owner))
        self.assertTrue(outcome.is_err())

    def test_create_returns_observed_ttl_instead_of_claiming_the_acknowledged_ttl_is_confirmed(self):
        original = self.http

        def old_ttl_on_readback(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "POST":
                record = response.json()["result"]
                ack = FakeResponse(200, {"success": True, "result": dict(record)})
                self.http.records[record["id"]]["ttl"] = 300
                return ack
            return response

        with patch(HTTP, old_ttl_on_readback):
            outcome = self.gateway.create_record(BINDING, replace(spec(), ttl=60))
        self.assertTrue(outcome.is_ok(), outcome)
        self.assertEqual(outcome.unwrap().spec.ttl, 300)

    def test_update_returns_observed_ttl_without_compensating_a_provider_still_converging(self):
        record_id = self.http.seed()
        original = self.http

        def old_ttl_on_readback(method, url, **kwargs):
            response = original(method, url, **kwargs)
            if method == "PUT":
                ack = FakeResponse(200, {"success": True, "result": dict(response.json()["result"])})
                self.http.records[record_id]["ttl"] = 300
                return ack
            return response

        with patch(HTTP, old_ttl_on_readback):
            outcome = self.gateway.update_record(BINDING, record_id, replace(spec(), ttl=60))
        self.assertTrue(outcome.is_ok(), outcome)
        self.assertEqual(outcome.unwrap().spec.ttl, 300)

    def test_record_delete_replay_accepts_authoritative_absence_in_the_still_bound_zone(self):
        record_id = self.http.seed()
        self.assertTrue(self.gateway.delete_record(BINDING, record_id, expected_owner_tag=OWNER).is_ok())
        self.assertTrue(self.gateway.delete_record(BINDING, record_id, expected_owner_tag=OWNER).is_ok())
        self.assertEqual(sum(method == "DELETE" for method, *_ in self.http.calls), 1)

    def test_zone_delete_replay_does_not_strand_a_job_after_a_successful_remote_delete(self):
        self.assertTrue(self.gateway.delete_zone(BINDING).is_ok())
        self.assertTrue(self.gateway.delete_zone(BINDING).is_ok())
        self.assertEqual(sum(method == "DELETE" for method, *_ in self.http.calls), 1)

    def test_zone_delete_checks_a_complete_fresh_inventory_before_its_single_delete(self):
        first = spec()
        second_uuid = "00000000-0000-4000-8000-000000000002"
        second = replace(
            first, local_id=second_uuid, name="www." + NAME, owner_tag=f"praho:hosted-zone-record:{second_uuid}"
        )
        self.http.seed()
        self.http.seed(2, name=second.name, comment=second.owner_tag)
        self.http.size = 1
        result = self.gateway.delete_zone(BINDING, expected_records=(first, second))
        self.assertTrue(result.is_ok(), result)
        operations = [(method, path) for method, path, *_ in self.http.calls]
        self.assertEqual(operations[-1], ("DELETE", f"/zones/{ZONE}"))
        self.assertEqual(operations.count(("GET", f"/zones/{ZONE}/dns_records")), 2)
        self.assertFalse(self.http.zones_exist)

    def test_zone_delete_refuses_records_added_changed_or_duplicated_during_moveaway_wait(self):
        for drift in ("added", "changed", "duplicate", "unowned", "unsupported"):
            with self.subTest(drift=drift):
                self.http.records.clear()
                self.http.calls.clear()
                record_id = self.http.seed()
                if drift == "changed":
                    self.http.records[record_id]["ttl"] = 900
                elif drift == "added":
                    self.http.seed(2, name="_new." + NAME, type="TXT", content='"not exported"', comment="")
                elif drift == "duplicate":
                    self.http.seed(2)
                elif drift == "unowned":
                    self.http.records[record_id]["comment"] = ""
                else:
                    self.http.seed(2, type="DNSKEY", content="257 3 13 broken", comment="")
                outcome = self.gateway.delete_zone(BINDING, expected_records=(spec(),))
                self.assertTrue(outcome.is_err())
                self.assertTrue(any(path.endswith("/dns_records") for _, path, *_ in self.http.calls))
                self.assertFalse(any(method == "DELETE" for method, *_ in self.http.calls))
                self.assertTrue(self.http.zones_exist)

    def test_zone_delete_whole_inventory_budget_expires_before_any_delete_dispatch(self):
        self.http.seed()
        clock = ManualClock()
        original = self.http

        def slow(method, url, **kwargs):
            response = original(method, url, **kwargs)
            clock.value += 45
            return response

        gateway = CloudflareZoneGateway(token="customer-zone-token", account_id=ACCOUNT, clock=clock, sleep=clock.sleep)
        with patch(HTTP, slow):
            result = gateway.delete_zone(BINDING, expected_records=(spec(),))
        self.assertTrue(result.is_err())
        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)
        self.assertFalse(any(method == "DELETE" for method, *_ in self.http.calls))

    def test_zone_delete_with_manifest_proof_still_recovers_a_successful_delete_replay(self):
        self.http.seed()
        self.assertTrue(self.gateway.delete_zone(BINDING, expected_records=(spec(),)).is_ok())
        self.assertTrue(self.gateway.delete_zone(BINDING, expected_records=(spec(),)).is_ok())
        self.assertEqual(sum(method == "DELETE" for method, *_ in self.http.calls), 1)

    def test_whole_inventory_deadline_includes_binding_and_every_page_and_never_returns_partial(self):
        for number in range(1, 8):
            self.http.seed(number)
        clock = ManualClock()
        original = self.http

        def slow(method, url, **kwargs):
            response = original(method, url, **kwargs)
            clock.value += 30
            return response

        gateway = CloudflareZoneGateway(token="customer-zone-token", account_id=ACCOUNT, clock=clock, sleep=clock.sleep)
        with patch(HTTP, slow):
            outcome = gateway.list_records(BINDING)
        self.assertTrue(outcome.is_err(), "A prefix of the zone must never be a complete inventory")
        self.assertEqual(len(self.http.calls), 3)
        self.assertEqual(retriability_of(outcome), Retriability.RETRIABLE)

    def test_retry_wait_cannot_consume_the_remaining_whole_call_deadline(self):
        for number in range(1, 8):
            self.http.seed(number)
        clock = ManualClock()
        original = self.http

        def slow_page(method, url, **kwargs):
            response = original(method, url, **kwargs)
            clock.value += 29
            if len(self.http.calls) == 3:
                return FakeResponse(429, {"success": False}, {"Retry-After": "5"})
            return response

        gateway = CloudflareZoneGateway(token="customer-zone-token", account_id=ACCOUNT, clock=clock, sleep=clock.sleep)
        with patch(HTTP, slow_page):
            outcome = gateway.list_records(BINDING)
        self.assertTrue(outcome.is_err())
        self.assertEqual(len(self.http.calls), 3)
        self.assertEqual(clock.sleeps, [])

    def test_deadline_after_a_post_keeps_its_unconfirmed_outcome_unknown(self):
        clock = ManualClock()
        original = self.http

        def slow(method, url, **kwargs):
            response = original(method, url, **kwargs)
            clock.value += 30
            return response

        gateway = CloudflareZoneGateway(token="customer-zone-token", account_id=ACCOUNT, clock=clock, sleep=clock.sleep)
        with patch(HTTP, slow):
            outcome = gateway.create_record(BINDING, spec())
        self.assertTrue(outcome.is_err())
        self.assertEqual(retriability_of(outcome), Retriability.UNKNOWN)
        self.assertEqual(sum(method == "POST" for method, *_ in self.http.calls), 1)


class ManualClock:
    def __init__(self):
        self.value = 0.0
        self.sleeps = []

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


class CustomerZoneSettingsTests(TestCase):
    def test_customer_zone_token_is_separate_sensitive_and_encrypted(self):
        self.assertTrue(CATALOG_BY_KEY[TOKEN_KEY].sensitive)
        self.assertEqual(CATALOG_BY_KEY[TOKEN_KEY].input_kind, "secret")
        result = SettingsService.update_setting(TOKEN_KEY, "customer-secret-token")
        self.assertTrue(result.is_ok(), result)
        row = SystemSetting.objects.get(key=TOKEN_KEY)
        self.assertTrue(row.is_sensitive)
        self.assertTrue(str(row.value).startswith("aes:v2:"))
        self.assertNotIn("customer-secret-token", str(row.value))
        self.assertEqual(SettingsService.get_setting(TOKEN_KEY), "customer-secret-token")

    def test_bulk_settings_cannot_set_the_token(self):
        result = SettingsService.apply_change_set({TOKEN_KEY: "secret"}, {TOKEN_KEY: None}, reason="test")
        self.assertTrue(result.is_err())
        self.assertFalse(SystemSetting.objects.filter(key=TOKEN_KEY).exists())

    def test_the_existing_write_only_secret_endpoint_can_set_and_clear_the_new_token(self):
        self.client.force_login(create_admin_user(username="zone_admin"))
        response = self.client.post(
            reverse("settings:secret_set", args=[TOKEN_KEY]),
            '{"value":"customer-secret-token","reason":"Configure zones"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertNotIn("customer-secret-token", response.content.decode())
        self.assertTrue(response.json()["configured"])
        response = self.client.post(
            reverse("settings:secret_clear", args=[TOKEN_KEY]),
            '{"reason":"Rotate customer-zone credentials"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(SettingsService.get_setting(TOKEN_KEY), "")

    def test_nonadmin_staff_cannot_set_customer_zone_credentials(self):
        self.client.force_login(create_staff_user(username="zone_staff", staff_role="support"))
        response = self.client.post(
            reverse("settings:secret_set", args=[TOKEN_KEY]), '{"value":"secret"}', content_type="application/json"
        )
        self.assertIn(response.status_code, (302, 403))

    def test_factory_reads_the_customer_zone_token_and_account_at_call_time(self):
        SettingsService.update_setting("dns.cloudflare_account_id", ACCOUNT).unwrap()
        SettingsService.update_setting(TOKEN_KEY, "customer-secret-token").unwrap()
        SettingsService.update_setting("dns.account_zone_api_token", "separate-name-token").unwrap()
        with patch(HTTP, Cloudflare()) as boundary:
            self.assertTrue(get_zone_gateway().read_zone(BINDING).is_ok())
        self.assertEqual(boundary.calls[0][-1]["Authorization"], "Bearer customer-secret-token")
