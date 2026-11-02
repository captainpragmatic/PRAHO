"""Page scripts find what they look for: the right element ids, the keys the API returns, the live Alpine API.

Each of these failed silently in the browser while every server-side test passed:
- the ticket form looked up `#subject` (the field renders as `#input-subject`), so changing the type threw;
- its services dropdown read `service_type`/`name`, which the API never returns: "undefined - undefined";
- the Virtualmin account page included the confirm modal a second time, so a second Confirm repeated the action;
- the unsaved-settings warning read `form.__x`, Alpine 2's API, so it never fired;
- the GDPR Cancel buttons called `closeModal`, which the shared modal.js replaces with `closeModal(modalId)`.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from tests.factories.core_factories import create_admin_user
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture
from tests.ui.node_harness import Markup, run_node

PLATFORM = Path(__file__).resolve().parents[2]


class TicketFormScriptTests(TestCase):
    def setUp(self) -> None:
        self.client.force_login(create_admin_user("ticket-script"))
        self.page = Markup(self.client.get(reverse("tickets:create")).content.decode())
        self.script = "\n".join(self.page.scripts)

    def test_every_element_the_script_looks_up_by_id_is_on_the_page(self) -> None:
        wanted = set(re.findall(r"getElementById\('([^']+)'\)", self.script))
        self.assertIn("ticket_type", wanted)  # the scan finds the lookups at all
        ids = {attrs.get("id") for _tag, attrs in self.page.elements}
        self.assertEqual(sorted(wanted - ids), [])

    def test_the_services_dropdown_reads_keys_the_api_returns(self) -> None:
        api = (PLATFORM / "apps/api/customers/views.py").read_text()
        returned = set(re.findall(r'"(\w+)"', re.search(r"\.values\(([^)]*)\)", api).group(1)))
        read = set(re.findall(r"service\.(\w+)", self.script))
        self.assertIn("id", read)
        self.assertEqual(sorted(read - returned), [])


class AccountDetailModalTests(VirtualminViewsFixture):
    def test_the_confirm_modal_is_on_the_page_once(self) -> None:
        html = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk])).content
        self.assertEqual(html.decode().count('x-data="dangerousActionModal"'), 1)


class GdprCancelTests(TestCase):
    def test_cancel_calls_the_pages_own_close_function_not_the_shared_one(self) -> None:
        self.client.force_login(create_admin_user("gdpr-cancel"))
        page = Markup(self.client.get(reverse("audit:gdpr_dashboard")).content.decode())
        invoked = {
            attrs["data-invoke"]
            for _tag, attrs in page.elements
            if attrs.get("data-invoke", "").lower().startswith("close")
        }
        self.assertTrue(invoked)
        self.assertNotIn("closeModal", invoked)  # modal.js (deferred) redefines window.closeModal(modalId)
        script = "\n".join(page.scripts)
        for name in invoked:
            self.assertRegex(script, rf"function {name}\(\)")


UNLOAD_HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
let unload;
const form = {};
const context = {
  console, Object,
  document: {addEventListener() {}, querySelector(s) { return s === "[data-settings-form]" ? form : null; }},
  window: {addEventListener(name, fn) { if (name === "beforeunload") unload = fn; }},
  Alpine: {data() {}, $data(el) { return el === form ? {dirty: input.dirty} : undefined; }},
};
context.window.Alpine = context.Alpine;
vm.runInNewContext(fs.readFileSync(input.source, "utf8"), context);
let prevented = false;
unload({preventDefault() { prevented = true; }});
process.stdout.write(JSON.stringify({prevented}));
"""


class UnsavedSettingsWarningTests(SimpleTestCase):
    def run_with(self, dirty: dict[str, bool]) -> bool:
        source = str(PLATFORM / "static/js/alpine-components.js")
        return bool(run_node(UNLOAD_HARNESS, {"source": source, "dirty": dirty})["prevented"])

    def test_leaving_with_unsaved_settings_warns_and_without_does_not(self) -> None:
        self.assertTrue(self.run_with({"billing.grace_days": True}))
        self.assertFalse(self.run_with({}))


DISCARD_HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
let unload, init;
const factories = {};
const form = {};
let component;
const context = {
  console, Object, Array, JSON,
  document: {
    addEventListener(name, fn) { if (name === "alpine:init") init = fn; },
    querySelector(s) { return s === "[data-settings-form]" ? form : null; },
  },
  window: {addEventListener(name, fn) { if (name === "beforeunload") unload = fn; }},
  Alpine: {data(name, fn) { factories[name] = fn; }, $data(el) { return el === form ? component : undefined; }},
};
context.Alpine.store = () => {};
context.window.Alpine = context.Alpine;
vm.runInNewContext(fs.readFileSync(input.source, "utf8"), context);
context.Alpine = context.window.Alpine;
init();
component = factories.settingsForm("/settings/save/");
component.dirty = {"billing.grace_days": true};
let prevented = null;
context.window.location = {reload() {  // the browser runs beforeunload as the reload starts
  prevented = false;
  unload({preventDefault() { prevented = true; }});
}};
component.discard();
process.stdout.write(JSON.stringify({prevented}));
"""


class DiscardDoesNotAskAgainTests(SimpleTestCase):
    def test_discard_reloads_without_the_unsaved_changes_prompt(self) -> None:
        """Discard is the user saying to drop the edits; the unload guard asked again, and Cancel kept them."""
        source = str(PLATFORM / "static/js/alpine-components.js")
        self.assertIs(run_node(DISCARD_HARNESS, {"source": source})["prevented"], False)
