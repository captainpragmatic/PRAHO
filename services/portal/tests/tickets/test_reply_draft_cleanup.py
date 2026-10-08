"""Exercise the reply cleanup listeners without losing a form that was not swapped."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const source = JSON.parse(fs.readFileSync(0, "utf8"));
const handlers = [];
const fields = {
  "char-counter": {textContent: "11"},
  "file-input": {value: "attachment.txt"},
  "file-list": {innerHTML: "attachment.txt", classList: {add() {}}},
  "submit-text": {textContent: "Sending..."},
  "submit-spinner": {classList: {add() {}}}
};
const button = {disabled: true};
const form = {
  id: "reply-form",
  message: "Draft reply",
  hasAttribute(name) { return name === "data-htmx-after"; },
  getAttribute() { return "reset-reply"; },
  reset() {
    this.message = "";
    fields["file-input"].value = "";
  }
};
const document = {
  body: {contains(el) { return el === form; }},
  addEventListener(name, callback) {
    if (name === "htmx:afterRequest") handlers.push(callback);
  },
  getElementById(id) { return fields[id] || null; },
  querySelector() { return button; }
};
vm.runInNewContext(source, {
  document, window: {}, setTimeout() {}, updateReplyCount() {}, console
});
for (const handler of handlers) {
  handler({detail: {elt: form, successful: true}});
}
process.stdout.write(JSON.stringify({
  message: form.message,
  attachment: fields["file-input"].value,
  counter: fields["char-counter"].textContent
}));
"""


class ReplyDraftCleanupTests(SimpleTestCase):
    def test_after_request_preserves_a_reply_form_that_was_not_swapped(self) -> None:
        portal = Path(settings.BASE_DIR)
        registry = (portal / "static/js/csp-actions.js").read_text(encoding="utf-8")
        template = (portal / "templates/tickets/ticket_detail.html").read_text(encoding="utf-8")
        inline = re.search(
            r"document.addEventListener\('htmx:afterRequest', function\(e\) \{.*?\n\}\);",
            template,
            flags=re.DOTALL,
        )
        assert inline is not None
        node = shutil.which("node")
        if node is None:
            self.fail("Node.js is required to exercise the portal reply listeners.")
        # Django strips {# #} comments when it renders the page, so run what the browser receives.
        rendered_inline = re.sub(r"\{#.*?#\}", "", inline.group())
        for name, source in (("registry", registry), ("ticket page", rendered_inline)):
            with self.subTest(listener=name):
                result = subprocess.run(  # noqa: S603 -- fixed local harness; no shell or remote input
                    [node, "-e", HARNESS],
                    input=json.dumps(source),
                    text=True,
                    capture_output=True,
                    check=True,
                    timeout=10,
                )
                self.assertEqual(
                    json.loads(result.stdout),
                    {"message": "Draft reply", "attachment": "attachment.txt", "counter": "11"},
                )
