"""platformFetch sends the page's CSRF token and turns a stale-token refusal into reload guidance.

fetch() callers used to read `[name=csrfmiddlewaretoken]` (null on a page with no form, so `.value` threw) and
parse every answer as JSON, so a refused token surfaced as a JSON error. The helper reads `<meta name="csrf-token">`,
and on a 403 marked `X-CSRF-Failure: reload` shows the page's reload message and rejects, without replaying.
"""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase

from tests.ui.node_harness import run_node

SOURCE = Path(__file__).resolve().parents[2] / "static" / "js" / "platform-actions.js"

HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const calls = [];
const toasts = [];
const metas = {"csrf-token": "T".repeat(64), "csrf-reload-message": "Reload, please"};
const context = {
  console,
  URL,
  document: {
    addEventListener() {},
    querySelector(selector) {
      const name = (selector.match(/meta\[name="([^"]+)"\]/) || [])[1];
      return name in metas ? {content: metas[name]} : null;
    },
  },
  location: {origin: "https://platform.test", href: "https://platform.test/x/"},
  showToast(kind, message) { toasts.push([kind, message]); },
  fetch(url, options) {
    calls.push({url, headers: options.headers, method: options.method});
    const marked = input.status === 403 && input.marked;
    return Promise.resolve({
      status: input.status,
      ok: input.status < 400,
      headers: {get(name) { return name === "X-CSRF-Failure" && marked ? "reload" : null; }},
    });
  },
};
context.window = context;
vm.runInNewContext(fs.readFileSync(input.source, "utf8"), context);
context.platformFetch("/settings/save/", {method: "POST", headers: {"Content-Type": "application/json"}})
  .then((response) => ({resolved: response.status}), (error) => ({rejected: error.message, csrf: !!error.csrfReload}))
  .then((outcome) => process.stdout.write(JSON.stringify({outcome, calls, toasts})));
"""


class PlatformFetchCsrfTests(SimpleTestCase):
    def run_with(self, status: int, marked: bool) -> dict[str, object]:
        return run_node(HARNESS, {"source": str(SOURCE), "status": status, "marked": marked})

    def test_it_sends_the_meta_token_and_keeps_the_callers_headers(self) -> None:
        result = self.run_with(200, marked=False)
        self.assertEqual(result["outcome"], {"resolved": 200})
        self.assertEqual(
            result["calls"],
            [
                {
                    "url": "/settings/save/",
                    "method": "POST",
                    "headers": {"Content-Type": "application/json", "X-CSRFToken": "T" * 64},
                }
            ],
        )
        self.assertEqual(result["toasts"], [])

    def test_a_stale_token_shows_reload_guidance_rejects_and_is_never_replayed(self) -> None:
        result = self.run_with(403, marked=True)
        self.assertEqual(result["outcome"], {"rejected": "Reload, please", "csrf": True})
        self.assertEqual(len(result["calls"]), 1)
        self.assertEqual(result["toasts"], [["error", "Reload, please"]])

    def test_a_refused_permission_is_left_to_the_caller(self) -> None:
        """An unmarked 403 is "not allowed", not a stale page: no reload guidance."""
        result = self.run_with(403, marked=False)
        self.assertEqual(result["outcome"], {"resolved": 403})
        self.assertEqual(result["toasts"], [])
