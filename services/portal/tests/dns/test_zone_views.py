"""Customer DNS pages use signed identities, current revisions and complete paginated receipts."""

import base64
import hashlib
import hmac
import json
import time
from html.parser import HTMLParser
from unittest.mock import patch
from uuid import UUID

import requests
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError
from apps.dns.services import DnsAPIClient, dns_api

ZONE_ID = "bf58f009-a492-4ad7-8a81-f69ef945a703"
RECORD_ID = "7d26136e-bd89-46cc-856c-aa5e1143fea5"
DIGEST = "a" * 64


class Inputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input" and attributes.get("name"):
            self.fields[attributes["name"]] = attributes


def record_payload(**changes):
    return {
        "id": RECORD_ID,
        "name": "customer.example",
        "record_type": "TXT",
        "ttl": 300,
        "rdata": '"keep mail unchanged"',
        "managed_by": "imported",
        "managed": False,
        "line": 3,
        "infrastructure": False,
        **changes,
    }


def zone_payload(**changes):
    return {
        "version": 1,
        "id": ZONE_ID,
        "name": "customer.example",
        "status": "pending_import",
        "revision": 2,
        "valid": True,
        "manifest_digest": DIGEST,
        "nameservers": [],
        "stale": False,
        "pending": False,
        "error": "",
        "errors": [],
        "page": 1,
        "page_size": 100,
        "pages": 1,
        "inventory_total": 1,
        "manifest_total": 1,
        "records_total": 1,
        "normalizations_total": 0,
        "inventory": [record_payload()],
        "manifest": [record_payload()],
        "records": [record_payload()],
        "normalizations": [],
        "crosscheck": {"complete": False, "ok": False},
        "dnssec": {},
        "can_switch_registrar": False,
        "export_digest": "",
        **changes,
    }


class DnsZoneClientTests(SimpleTestCase):
    def setUp(self):
        self.api = DnsAPIClient()

    def test_every_call_signs_customer_and_user_and_posts_json(self):
        with patch.object(
            self.api, "_make_request", return_value={"success": True, "data": {"zone": zone_payload()}}
        ) as call:
            self.api.zone_detail(42, 7, UUID(ZONE_ID), page=2)
        self.assertEqual(call.call_args.args, ("POST", f"/dns/zones/{ZONE_ID}/"))
        self.assertEqual(call.call_args.kwargs["data"], {"customer_id": 42, "user_id": 7, "page": 2})
        self.assertEqual(call.call_args.kwargs["user_id"], 7)
        self.assertTrue(call.call_args.kwargs["idempotent"])

    def test_import_encodes_browser_file_as_signed_json_without_retrying_creation(self):
        raw = b'$ORIGIN customer.example.\n@ 300 IN TXT "keep"\n'
        with patch.object(
            self.api, "_make_request", return_value={"success": True, "data": {"zone": zone_payload()}}
        ) as call:
            self.api.import_zone(42, 7, 5, raw)
        self.assertEqual(call.call_args.kwargs["data"]["zone_file"], base64.b64encode(raw).decode())
        self.assertEqual(call.call_args.kwargs["data"]["service_id"], 5)
        self.assertFalse(call.call_args.kwargs.get("idempotent", False))

    def test_malformed_receipts_and_invented_switch_readiness_are_refused(self):
        for value in (
            [],
            None,
            {"success": True, "data": {}},
            {"success": True, "data": {"zone": zone_payload(version=True)}},
            {
                "success": True,
                "data": {"zone": zone_payload(nameservers=["ns.example"], stale=True, can_switch_registrar=True)},
            },
            {"success": True, "data": {"zone": zone_payload(records="bad")}},
        ):
            with (
                self.subTest(value=value),
                patch.object(self.api, "_make_request", return_value=value),
                self.assertRaises(PlatformAPIError),
            ):
                self.api.zone_detail(42, 7, UUID(ZONE_ID))

    def test_public_projection_discards_private_provider_and_node_metadata(self):
        payload = zone_payload(private_node="node-secret", provider_token="secret")
        payload["records"][0]["private_evidence"] = "never render"
        with patch.object(self.api, "_make_request", return_value={"success": True, "data": {"zone": payload}}):
            result = self.api.zone_detail(42, 7, UUID(ZONE_ID))
        self.assertNotIn("private_node", result)
        self.assertNotIn("provider_token", result)
        self.assertNotIn("private_evidence", result["records"][0])

    def test_manual_registrar_receipt_preserves_ready_nameservers_without_switch_capability(self):
        payload = zone_payload(status="awaiting_ns", nameservers=["one.ns.example", "two.ns.example"])
        with patch.object(self.api, "_make_request", return_value={"success": True, "data": {"zone": payload}}):
            result = self.api.zone_detail(42, 7, UUID(ZONE_ID))
        self.assertEqual(result["nameservers"], payload["nameservers"])
        self.assertFalse(result["can_switch_registrar"])

    def test_real_http_body_and_hmac_bind_zone_page_to_canonical_customer_and_user(self):
        self.api.base_url = "https://platform.internal/api"
        self.api.portal_id = "dns-portal"
        self.api.portal_secret = "portal-dns-test-secret-" + "x" * 40
        response = requests.Response()
        response.status_code = 200
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps({"success": True, "data": {"zone": zone_payload()}}).encode()
        with patch("apps.api_client.services.portal_request", return_value=response) as send:
            self.api.zone_detail(42, 7, UUID(ZONE_ID), page=3)
        wire = send.call_args.kwargs
        body, headers = wire["data"], wire["headers"]
        payload = json.loads(body)
        self.assertEqual((payload["customer_id"], payload["user_id"], payload["page"]), (42, 7, 3))
        self.assertEqual(str(payload["timestamp"]), headers["X-Timestamp"])
        self.assertEqual(wire["method"], "POST")
        self.assertIsNone(wire["params"])
        body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode()
        canonical = "\n".join(
            [
                "POST",
                f"/api/dns/zones/{ZONE_ID}/",
                "application/json",
                body_hash,
                "dns-portal",
                headers["X-Nonce"],
                headers["X-Timestamp"],
            ]
        )
        expected = hmac.new(self.api.portal_secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-Signature"], expected)

    def test_malformed_record_identifiers_are_unavailable_before_template_reversal(self):
        payload = zone_payload(records=[record_payload(id="not-a-uuid")])
        with (
            patch.object(self.api, "_make_request", return_value={"success": True, "data": {"zone": payload}}),
            self.assertRaises(PlatformAPIError),
        ):
            self.api.zone_detail(42, 7, UUID(ZONE_ID))

    def test_complete_zone_upload_and_export_use_the_agreed_two_mib_cap(self):
        raw = b"; complete canonical zone\n" + b" " * (300 * 1024)
        with patch.object(self.api, "_make_request", return_value={"success": True, "data": {"zone": zone_payload()}}):
            self.api.import_zone(42, 7, 5, raw)
        with patch.object(
            self.api,
            "_make_request",
            return_value={"success": True, "data": {"zone_file": base64.b64encode(raw).decode()}},
        ):
            self.assertEqual(self.api.export_zone(42, 7, UUID(ZONE_ID)), raw)

    def test_invalid_import_keeps_full_inventory_and_safe_structured_line_error(self):
        payload = zone_payload(
            valid=False,
            errors=[{"code": "unsupported_records", "line": 9}],
            inventory=[record_payload(record_type="DS")],
            manifest=[],
            manifest_total=0,
        )
        with patch.object(self.api, "_make_request", return_value={"success": True, "data": {"zone": payload}}):
            result = self.api.zone_detail(42, 7, UUID(ZONE_ID))
        self.assertFalse(result["valid"])
        self.assertEqual(result["inventory"][0]["record_type"], "DS")
        self.assertEqual(result["errors"], [{"code": "unsupported_records", "line": 9}])


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
)
class DnsZoneViewsTests(SimpleTestCase):
    path = f"/dns/zones/{ZONE_ID}/"

    def setUp(self):
        self.login_as("owner")
        self.read = self.enterContext(patch.object(dns_api, "zone_detail", return_value=zone_payload()))
        self.action = self.enterContext(patch.object(dns_api, "zone_action", return_value=zone_payload(pending=True)))

    def login_as(self, role, client=None):
        session = (client or self.client).session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "user_memberships": [{"customer_id": 42, "role": role}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()

    def test_members_read_escaped_full_inventory_without_provider_metadata(self):
        for role in ("owner", "tech", "billing", "viewer"):
            with self.subTest(role=role):
                self.login_as(role)
                response = self.client.get(self.path)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "keep mail unchanged")
                self.assertContains(response, "External mail")
                self.assertEqual(response["Cache-Control"], "private, no-store")

    def test_customer_zone_states_have_human_labels_on_detail_and_list(self):
        for state, label in (
            ("pending_import", "Import pending"),
            ("awaiting_ns", "Awaiting nameserver change"),
            ("active", "Active"),
            ("deleting", "Deletion in progress"),
            ("deleted", "Deleted"),
            ("failed", "Needs attention"),
            ("private_worker_state", "Status unavailable"),
        ):
            with self.subTest(state=state):
                self.read.return_value = zone_payload(status=state)
                response = self.client.get(self.path)
                self.assertContains(response, label)
                self.assertNotContains(response, f"· {state}</p>")
                self.assertEqual(response.context["zone"]["status"], state)
                data = {
                    "zones": [{"id": ZONE_ID, "name": "customer.example", "status": state, "revision": 2}],
                    "page": 1,
                    "pages": 1,
                    "total": 1,
                }
                with patch.object(dns_api, "zone_list", return_value=data):
                    listed = self.client.get("/dns/")
                self.assertContains(listed, label)
                self.assertNotContains(listed, f">{state}</span>")

    def test_normalization_labels_explain_changes_without_internal_codes(self):
        for kind, label in (
            ("managed_frontend", "Managed hosting records"),
            ("duplicate_collapsed", "Duplicate record removed"),
            ("customer_record_change", "DNS record changes"),
            ("private_provider_state", "DNS record adjustment"),
        ):
            with self.subTest(kind=kind):
                self.read.return_value = zone_payload(
                    normalizations=[{"kind": kind, **record_payload()}], normalizations_total=1
                )
                response = self.client.get(self.path)
                self.assertContains(response, label)
                self.assertNotContains(response, f">{kind}</p>")
                self.assertEqual(response.context["zone"]["normalizations"][0]["kind"], kind)

    def test_page_two_reaches_platform_and_preserves_pagination_links(self):
        self.read.return_value = zone_payload(
            page=2, pages=3, inventory_total=201, manifest_total=201, records_total=201
        )
        response = self.client.get(self.path + "?page=2")
        self.read.assert_called_once_with(42, 7, UUID(ZONE_ID), page=2)
        self.assertContains(response, "?page=1")
        self.assertContains(response, "?page=3")

    def test_mutations_require_owner_or_tech_and_csrf(self):
        for role in ("billing", "viewer"):
            self.login_as(role)
            self.assertEqual(
                self.client.post(
                    self.path + "confirm/", {"expected_revision": 2, "manifest_digest": DIGEST, "confirmed": "on"}
                ).status_code,
                403,
            )
        self.action.assert_not_called()
        strict = Client(enforce_csrf_checks=True)
        self.login_as("owner", strict)
        self.assertEqual(strict.post(self.path + "confirm/").status_code, 403)

    def test_confirm_requires_explicit_acknowledgement_and_posts_exact_revision_digest(self):
        self.assertEqual(
            self.client.post(self.path + "confirm/", {"expected_revision": 2, "manifest_digest": DIGEST}).status_code,
            400,
        )
        self.action.assert_not_called()
        response = self.client.post(
            self.path + "confirm/", {"expected_revision": 2, "manifest_digest": DIGEST, "confirmed": "on"}
        )
        self.assertEqual(response.status_code, 303)
        self.action.assert_called_once_with(
            42, 7, UUID(ZONE_ID), "confirm", {"expected_revision": 2, "manifest_digest": DIGEST}
        )

    def test_browser_checked_confirmation_submits_a_true_value(self):
        self.read.return_value = zone_payload(status="pending_import", crosscheck={"complete": True, "ok": True})
        rendered = Inputs()
        rendered.feed(self.client.get(self.path).content.decode())
        field = rendered.fields["confirmed"]
        response = self.client.post(
            self.path + "confirm/",
            {"expected_revision": 2, "manifest_digest": DIGEST, "confirmed": field.get("value", "on")},
        )
        self.assertEqual(response.status_code, 303)

    def test_confirmation_waits_for_source_inventory_crosscheck(self):
        self.assertNotContains(self.client.get(self.path), "Confirm this exact import")
        self.read.return_value = zone_payload(crosscheck={"complete": True, "ok": True})
        self.assertContains(self.client.get(self.path), "Confirm this exact import")

    def test_htmx_success_redirects_and_stale_conflict_does_not_promise_success(self):
        response = self.client.post(self.path + "crosscheck/", {"expected_revision": 2}, HTTP_HX_REQUEST="true")
        self.assertEqual(response["HX-Redirect"], self.path)
        self.action.side_effect = PlatformAPIError("node-secret 10.0.0.5 token", status_code=409)
        response = self.client.post(self.path + "crosscheck/", {"expected_revision": 2}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("HX-Redirect", response)
        self.assertIn("showToast", response["HX-Trigger"])
        self.assertNotIn("node-secret", response["HX-Trigger"])
        self.assertNotContains(response, "node-secret", status_code=409)

    def test_nameserver_instructions_require_fresh_ready_receipt(self):
        self.read.return_value = zone_payload(status="pending_import", nameservers=[], pending=True)
        response = self.client.get(self.path)
        self.assertNotContains(response, "Change your registrar")
        self.read.return_value = zone_payload(
            status="awaiting_ns", nameservers=["one.ns.example", "two.ns.example"], can_switch_registrar=True
        )
        response = self.client.get(self.path)
        self.assertContains(response, "Change your registrar")
        self.assertContains(response, "one.ns.example")

    def test_ready_external_registrar_gets_manual_ns_instructions_without_automated_switch(self):
        self.read.return_value = zone_payload(status="awaiting_ns", nameservers=["one.ns.example", "two.ns.example"])
        response = self.client.get(self.path)
        self.assertContains(response, "Change your registrar")
        self.assertContains(response, "one.ns.example")
        self.assertNotContains(response, "Update nameservers through registrar")

    def test_registrar_nameserver_update_requires_an_explicit_confirmation(self):
        response = self.client.post(self.path + "switch/", {"expected_revision": 2})
        self.assertEqual(response.status_code, 400)
        self.action.assert_not_called()

    def test_pending_polling_is_bounded_and_preserves_current_page(self):
        self.read.return_value = zone_payload(pending=True, page=2, pages=2, records_total=101)
        self.assertContains(self.client.get(self.path + "?page=2&poll=0"), "page=2&amp;poll=1")
        response = self.client.get(self.path + "?page=2&poll=12")
        self.assertNotContains(response, 'hx-trigger="load delay:')

    def test_foreign_and_revoked_errors_are_safe_and_do_not_render_zone(self):
        for code in (403, 404, 503):
            self.read.side_effect = PlatformAPIError("secret provider evidence", status_code=code)
            response = self.client.get(self.path)
            self.assertEqual(response.status_code, code)
            self.assertNotContains(response, "secret provider", status_code=code)

    def test_import_uses_existing_service_domain_and_rejects_raw_id_tampering(self):
        with (
            patch(
                "apps.dns.views.services_api.get_service_detail",
                return_value={
                    "id": 5,
                    "domain": "customer.example",
                    "hosting": {"account_name": "a1.accounts.example"},
                },
            ),
            patch.object(dns_api, "import_zone", return_value=zone_payload()) as imported,
        ):
            response = self.client.get("/dns/import/5/")
            self.assertContains(response, "customer.example")
            response = self.client.post(
                "/dns/import/5/", {"service_id": 999, "zone_file": SimpleUploadedFile("zone.txt", b"@ 300 IN TXT keep")}
            )
            self.assertEqual(response.status_code, 303)
            self.assertEqual(imported.call_args.args[:3], (42, 7, 5))

    def test_record_form_is_typed_and_managed_records_are_read_only(self):
        with patch.object(
            dns_api, "record_detail", return_value={"record": record_payload(managed=True), "revision": 2}
        ):
            self.assertEqual(self.client.get(self.path + f"records/{RECORD_ID}/").status_code, 409)
        response = self.client.get(self.path + "records/new/")
        self.assertContains(response, "DNS notation")
        self.assertContains(response, "AAAA")

    def test_delete_requires_real_export_receipt_and_explicit_move_away_intent(self):
        response = self.client.post(
            self.path + "delete/", {"expected_revision": 2, "confirmed": "on", "moved_away": "on"}
        )
        self.assertEqual(response.status_code, 400)
        self.action.assert_not_called()
        response = self.client.get(self.path + "delete/")
        self.assertContains(response, "Export")
        self.assertNotContains(response, 'name="export_digest"')

    def test_list_pages_are_not_truncated_and_selected_identity_is_signed(self):
        data = {
            "zones": [{"id": ZONE_ID, "name": "customer.example", "status": "active", "revision": 2}],
            "page": 2,
            "pages": 3,
            "total": 51,
        }
        with patch.object(dns_api, "zone_list", return_value=data) as listed:
            response = self.client.get("/dns/?page=2&customer_id=999&user_id=999")
        listed.assert_called_once_with(42, 7, page=2)
        self.assertContains(response, "?page=1")
        self.assertContains(response, "?page=3")

    def test_private_evidence_and_record_markup_are_not_executed_or_rendered(self):
        self.read.return_value = zone_payload(
            records=[record_payload(rdata='<script>alert("x")</script>')], private_node="node-secret"
        )
        response = self.client.get(self.path)
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, '<script>alert("x")</script>')
        self.assertNotContains(response, "node-secret")

    def test_owner_and_tech_submit_typed_record_changes_with_exact_revision(self):
        with patch.object(dns_api, "change_record", return_value=zone_payload()) as changed:
            for role in ("owner", "tech"):
                self.login_as(role)
                response = self.client.post(
                    self.path + "records/new/",
                    {
                        "expected_revision": 2,
                        "name": "_verify.customer.example",
                        "record_type": "TXT",
                        "rdata": '"verify"',
                        "ttl": 300,
                    },
                )
                self.assertEqual(response.status_code, 303)
                self.assertEqual(
                    changed.call_args.args,
                    (
                        42,
                        7,
                        UUID(ZONE_ID),
                        None,
                        {
                            "expected_revision": 2,
                            "name": "_verify.customer.example",
                            "record_type": "TXT",
                            "rdata": '"verify"',
                            "ttl": 300,
                        },
                    ),
                )
            response = self.client.post(
                self.path + "records/new/",
                {
                    "expected_revision": 2,
                    "name": "customer.example",
                    "record_type": "PTR",
                    "rdata": "foreign.",
                    "ttl": 30,
                },
            )
            self.assertEqual(response.status_code, 400)
            self.assertEqual(changed.call_count, 2)

    def test_record_delete_requires_working_confirmation_without_javascript(self):
        path = self.path + f"records/{RECORD_ID}/delete/"
        with (
            patch.object(dns_api, "record_detail", return_value={"record": record_payload(), "revision": 2}),
            patch.object(dns_api, "change_record", return_value=zone_payload()) as changed,
        ):
            self.assertEqual(self.client.get(path).status_code, 200)
            changed.assert_not_called()
            self.assertEqual(self.client.post(path, {"expected_revision": 2}).status_code, 400)
            changed.assert_not_called()
            response = self.client.post(path, {"expected_revision": 2, "confirmed": "on"})
            self.assertEqual(response.status_code, 303)
            changed.assert_called_once_with(
                42, 7, UUID(ZONE_ID), UUID(RECORD_ID), {"expected_revision": 2, "delete": True}
            )

    def test_viewer_can_download_real_export_and_mutations_remain_blocked(self):
        self.login_as("viewer")
        with patch.object(dns_api, "export_zone", return_value=b'@ 300 IN TXT "keep"\n') as exported:
            self.assertEqual(self.client.get(self.path + "export/").status_code, 405)
            response = self.client.post(self.path + "export/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'@ 300 IN TXT "keep"\n')
        self.assertIn("attachment", response["Content-Disposition"])
        exported.assert_called_once_with(42, 7, UUID(ZONE_ID))

    def test_real_export_digest_and_both_confirmations_queue_delete_intent(self):
        self.read.return_value = zone_payload(export_digest=DIGEST)
        response = self.client.post(
            self.path + "delete/",
            {"expected_revision": 2, "export_digest": DIGEST, "moved_away": "on", "confirmed": "on"},
        )
        self.assertEqual(response.status_code, 303)
        self.action.assert_called_once_with(
            42, 7, UUID(ZONE_ID), "delete", {"expected_revision": 2, "export_digest": DIGEST}
        )

    def test_deleted_hosting_binding_does_not_strand_independently_owned_zone_deletion(self):
        self.read.return_value = zone_payload(stale=True, export_digest=DIGEST)
        response = self.client.get(self.path + "delete/")
        self.assertContains(response, 'name="export_digest"')
        response = self.client.post(
            self.path + "delete/",
            {"expected_revision": 2, "export_digest": DIGEST, "moved_away": "on", "confirmed": "on"},
        )
        self.assertEqual(response.status_code, 303)
        self.action.assert_called_once_with(
            42, 7, UUID(ZONE_ID), "delete", {"expected_revision": 2, "export_digest": DIGEST}
        )

    def test_independent_zone_can_still_offer_customer_records_after_hosting_is_removed(self):
        self.read.return_value = zone_payload(stale=True)
        self.assertContains(self.client.get(self.path), "Add DNS record")

    def test_service_enrollment_link_is_technical_but_zone_browsing_is_for_every_member(self):
        service = {
            "id": 5,
            "status": "active",
            "service_name": "Hosting",
            "domain": "customer.example",
            "currency_code": "RON",
            "hosting": {"account_name": "a1.accounts.example", "records": []},
        }
        with patch("apps.services.views.services_api") as api:
            api.get_service_detail.return_value = service
            api.get_service_usage.return_value = {}
            api.get_service_domains.return_value = []
            for role in ("owner", "tech", "billing", "viewer"):
                self.login_as(role)
                response = self.client.get("/services/5/")
                self.assertContains(response, "Your DNS zones")
                if role in {"owner", "tech"}:
                    self.assertContains(response, "Import DNS for this hosting domain")
                else:
                    self.assertNotContains(response, "Import DNS for this hosting domain")

    def test_desktop_and_mobile_navigation_keep_dns_zones_accessible_without_hosting(self):
        self.login_as("viewer")
        service = {
            "id": 5,
            "status": "terminated",
            "service_name": "Former hosting",
            "domain": "customer.example",
            "currency_code": "RON",
            "hosting": None,
        }
        with patch("apps.services.views.services_api") as api:
            api.get_service_detail.return_value = service
            api.get_service_usage.return_value = {}
            api.get_service_domains.return_value = []
            response = self.client.get("/services/5/")
        self.assertContains(response, 'href="/dns/"', count=2)
        self.assertNotContains(response, "Import DNS for this hosting domain")

    def test_small_screens_get_labeled_complete_record_cards_and_desktop_keeps_its_table(self):
        row = record_payload(
            name="selector-with-a-long-name._domainkey.customer.example",
            rdata='"A long verification value that must remain fully readable"',
        )
        self.read.return_value = zone_payload(inventory=[row], manifest=[row], records=[row])
        page = self.client.get(self.path).content.decode()
        self.assertIn('data-testid="dns-record-cards"', page)
        self.assertIn('data-testid="dns-record-table"', page)
        original_cards = page.split('data-testid="dns-record-cards"', 1)[1].split('data-testid="dns-record-table"', 1)[
            0
        ]
        self.assertNotIn("Edit", original_cards, "The historical inventory has no record mutation controls")
        current = page.split("Current records", 1)[1]
        cards = current.split('data-testid="dns-record-cards"', 1)[1].split('data-testid="dns-record-table"', 1)[0]
        for label in ("Name", "Type", "TTL", "Value", "Control"):
            self.assertIn(label, cards)
        self.assertIn(row["name"], cards)
        self.assertIn("A long verification value that must remain fully readable", cards)
        self.assertIn("Edit", cards)
        self.assertIn("md:hidden", page)
        self.assertIn("hidden md:block", page)

    def test_unreadable_receipt_is_unavailable_in_real_view_without_raw_exception(self):
        self.read.side_effect = lambda *args, **kwargs: DnsAPIClient.zone_detail(dns_api, *args, **kwargs)
        with patch.object(dns_api, "_make_request", return_value=[]):
            response = self.client.get(self.path)
        self.assertEqual(response.status_code, 503)
        self.assertNotContains(response, "Traceback", status_code=503)
