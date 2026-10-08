"""The ticket validator must leave the real mobile Sign Out POST alone."""

from __future__ import annotations

import json
import shutil
import subprocess
from html.parser import HTMLParser
from typing import cast

from django.contrib.sessions.backends.signed_cookies import SessionStore
from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase
from django.urls import reverse
from django.utils import translation

HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const forms = input.forms.map(attrs => ({
  ...attrs, handlers: {},
  addEventListener(name, fn) { this.handlers[name] = fn; }
}));
const fields = Object.fromEntries(input.ids.map(id => [id, {
  value: "", textContent: "", hidden: true,
  addEventListener() {},
  classList: {remove() { fields[id].hidden = false; }},
  scrollIntoView() {}
}]));
const document = {
  getElementById(id) { return forms.find(form => form.id === id) || fields[id]; },
  querySelector(selector) {
    if (selector === "form") return forms[0];
    throw new Error("Unexpected selector: " + selector);
  }
};
vm.runInNewContext(input.source, {document, console});
function submit(form) {
  let prevented = false;
  if (form.handlers.submit) form.handlers.submit({preventDefault() { prevented = true; }});
  return prevented;
}
const logout = forms[0];
const ticket = forms.find(form => !form.action);
const logoutPrevented = submit(logout);
const ticketPrevented = submit(ticket);
const error = fields["form-error-message"].textContent;
const errorVisible = !fields["form-error"].hidden;
fields.title.value = "Connection issue";
fields.description.value = "The hosting service is unavailable.";
const validTicketPrevented = submit(ticket);
process.stdout.write(JSON.stringify({
  logoutAction: logout.action, logoutPrevented, ticketPrevented,
  error, errorVisible, validTicketPrevented
}));
"""


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, str]] = []
        self.ids: list[str] = []
        self.scripts: list[str] = []
        self._script: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value or "" for name, value in attrs}
        if tag == "form":
            self.forms.append(attributes)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "script" and "src" not in attributes:
            self._script = []

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._script is not None:
            self.scripts.append("".join(self._script))
            self._script = None


class TicketCreateValidationTests(SimpleTestCase):
    def test_mobile_logout_posts_while_empty_tickets_are_rejected(self) -> None:
        request = RequestFactory().get("/tickets/create/")
        request.session = SessionStore()
        request.session["customer_id"] = "test-customer"
        with translation.override("en"):
            markup = render_to_string("tickets/ticket_create.html", {"request": request, "csrf_token": "test-token"})
        page = _Page()
        page.feed(markup)
        self.assertEqual(len(page.forms), 3)  # Mobile logout, desktop logout, ticket.
        self.assertEqual(page.forms[0]["action"], reverse("users:logout"))
        self.assertEqual(page.forms[0]["method"], "post")
        sources = [script for script in page.scripts if "// Form validation helper" in script]
        self.assertEqual(len(sources), 1)
        node = shutil.which("node")
        if node is None:
            self.fail("Node.js is required to exercise ticket form validation.")
        result = subprocess.run(  # noqa: S603 -- fixed local harness, no shell or remote input
            [node, "-e", HARNESS],
            input=json.dumps({"forms": page.forms, "ids": page.ids, "source": sources[0]}),
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        )
        output = cast("dict[str, object]", json.loads(result.stdout))
        self.assertFalse(output["logoutPrevented"], "The mobile Sign Out POST must not be cancelled.")
        self.assertTrue(output["ticketPrevented"])
        self.assertTrue(output["errorVisible"])
        self.assertEqual(output["error"], "Please fill in both title and description fields.")
        self.assertFalse(output["validTicketPrevented"])
