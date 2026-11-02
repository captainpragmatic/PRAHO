"""The order edit page keeps the newest financial summary when two refreshes overlap.

Each item change refreshes the summary with its own request. The swap first wrote to the element captured before the
fetch, so when two overlapped the second wrote to a node the first had already replaced, and the browser threw.
Looking the element up again stopped that, but let an older answer that arrived last overwrite a newer one. Only the
latest refresh may swap.
"""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase

from tests.ui.node_harness import run_node

SCRIPT = Path(__file__).resolve().parents[2] / "static" / "js" / "orders-items.js"

HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const payload = JSON.parse(fs.readFileSync(0, "utf8"));

function anything() {  // stands in for the DOM bits a notification touches
  const f = function () { return anything(); };
  return new Proxy(f, { get: (t, k) => (k === Symbol.toPrimitive ? () => "" : anything()), set: () => true });
}
const elements = {};
function summary(text) {
  const el = { text, attached: true };
  Object.defineProperty(el, "outerHTML", {
    get() { return el.text; },
    set(html) {
      if (!el.attached) { throw new Error("NoModificationAllowedError: This element has no parent node."); }
      el.attached = false;
      elements["financial-summary"] = summary(html);
    },
  });
  return el;
}
elements["financial-summary"] = summary("0");

const pending = [];
const document = {
  getElementById: (id) => elements[id] || null,
  querySelector: () => null,
  addEventListener: () => {},
  createElement: () => anything(),
  body: anything(),
};
const window = {
  PRAHO_ORDER_ITEMS: { orderUrl: "/orders/1/", i18n: {}, icons: {} },
  addEventListener: () => {},
  confirm: () => true,
  alert: () => {},
  platformFetch: () => Promise.resolve({ json: () => ({ success: true }) }),
};
const errors = [];
const context = {
  window, document, setTimeout: () => 0, clearTimeout: () => {},
  console: { error: (...a) => errors.push(a.join(" ")), log: () => {}, warn: () => {} },
  DOMParser: function () {
    this.parseFromString = (html) => ({
      getElementById: (id) => (id === "financial-summary" ? { outerHTML: html } : null),
      querySelector: () => null,
    });
  },
  fetch: (url) => new Promise((resolve) => pending.push({ url, resolve })),
};
vm.createContext(context);
vm.runInContext(payload.source, context);

const tick = () => new Promise((r) => setImmediate(r));
(async () => {
  window.deleteOrderItem("a");
  window.deleteOrderItem("b");
  for (let i = 0; i < 5; i++) { await tick(); }
  // Both totals requests answer; each starts a summary refresh.
  pending.splice(0).forEach((p) => p.resolve({ text: () => "" }));
  for (let i = 0; i < 5; i++) { await tick(); }
  const [older, newer] = pending.splice(0);
  newer.resolve({ text: () => "200" });
  for (let i = 0; i < 5; i++) { await tick(); }
  older.resolve({ text: () => "100" });
  for (let i = 0; i < 5; i++) { await tick(); }
  process.stdout.write(JSON.stringify({
    summary: elements["financial-summary"].text,
    urls: [older.url, newer.url],
    errors,
  }));
})();
"""


class SummaryRefreshTests(SimpleTestCase):
    def test_the_newest_refresh_wins_when_answers_arrive_out_of_order(self) -> None:
        result = run_node(HARNESS, {"source": SCRIPT.read_text(encoding="utf-8")})
        self.assertEqual(result["urls"], ["/orders/1/", "/orders/1/"])  # both are summary refreshes
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["summary"], "200")
