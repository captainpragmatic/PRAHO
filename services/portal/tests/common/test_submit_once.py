"""A form marked submit-once reaches the server once per click burst, and can be sent again later.

Confirming your identity turns the session key before Platform is asked (ADR-0017 section 7); a second
submit of the same key would lose that race and could sign the browser out, so the confirm form drops
a repeat sent within ten seconds of the first. A page restored later, or a retry, still submits.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const source = JSON.parse(fs.readFileSync(0, "utf8"));
const submitHandlers = [];
const document = {
  addEventListener(name, callback) { if (name === "submit") submitHandlers.push(callback); },
};
let clock = 1000000;
const FakeDate = {now() { return clock; }};
const form = {dataset: {submitOnce: ""}, closest(selector) {
  return selector === "form[data-submit-once]" ? form : null;
}};
function submit() {
  const event = {target: form, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }};
  for (const handler of submitHandlers) handler(event);
  return !event.defaultPrevented;
}
vm.runInNewContext(source, {document, window: {}, Date: FakeDate, Number, String, setTimeout() {}, console});
const sent = [submit()];
clock += 300; sent.push(submit());     // a double click
clock += 10000; sent.push(submit());   // a retry ten seconds later
process.stdout.write(JSON.stringify(sent));
"""


class SubmitOnceTests(SimpleTestCase):
    def test_a_repeat_within_ten_seconds_is_dropped_and_a_later_one_is_sent(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.fail("Node.js is required to exercise the portal's form listeners.")
        source = (Path(settings.BASE_DIR) / "static/js/csp-actions.js").read_text(encoding="utf-8")
        result = subprocess.run(  # noqa: S603 -- fixed local harness; no shell or remote input
            [node, "-e", HARNESS], input=json.dumps(source), text=True, capture_output=True, check=True
        )
        self.assertEqual(json.loads(result.stdout), [True, False, True])
