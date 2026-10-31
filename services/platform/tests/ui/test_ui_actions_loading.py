"""A `{% button loading=True %}` shows its spinner while its plain form submits.

The spinner markup alone shows nothing: `.btn-spinner` is hidden until the button has `.is-loading`
(assets/css/input.css). shared/ui/static/js/ui-actions.js adds it at submit, leaves a form a script intercepted alone,
and clears it when back/forward restores the page from the cache.
"""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase

from tests.ui.node_harness import run_node

SOURCE = Path(__file__).resolve().parents[4] / "shared" / "ui" / "static" / "js" / "ui-actions.js"

HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const listeners = {document: {}, window: {}};
function element(loading) {
  const classes = new Set(["ui-btn"]);
  const attributes = loading ? {"data-loading": ""} : {};
  return {
    classList: {add(c) { classes.add(c); }, remove(c) { classes.delete(c); }, contains(c) { return classes.has(c); }},
    setAttribute(n, v) { attributes[n] = v; },
    removeAttribute(n) { delete attributes[n]; },
    matches(selector) { return selector === ".ui-btn[data-loading]" && "data-loading" in attributes; },
    state() { return {loading: classes.has("is-loading"), busy: attributes["aria-busy"] || null}; },
  };
}
const buttons = {plain: element(true), intercepted: element(true), other: element(false)};
const context = {
  console,
  Object,
  document: {
    addEventListener(name, fn) { (listeners.document[name] = listeners.document[name] || []).push(fn); },
    querySelectorAll() { return [buttons.plain, buttons.intercepted].filter((b) => b.classList.contains("is-loading")); },
  },
  window: {addEventListener(name, fn) { (listeners.window[name] = listeners.window[name] || []).push(fn); }},
};
vm.runInNewContext(fs.readFileSync(input.source, "utf8"), context);
function submit(button, prevented) {
  for (const fn of listeners.document.submit || []) fn({submitter: button, defaultPrevented: prevented});
}
submit(buttons.plain, false);
submit(buttons.intercepted, true);
submit(buttons.other, false);
const atSubmit = {plain: buttons.plain.state(), intercepted: buttons.intercepted.state(), other: buttons.other.state()};
for (const fn of listeners.window.pageshow || []) fn({persisted: true});
process.stdout.write(JSON.stringify({atSubmit, afterRestore: buttons.plain.state()}));
"""


class SubmitLoadingTests(SimpleTestCase):
    def test_a_plain_submit_shows_the_spinner_and_a_restored_page_clears_it(self) -> None:
        result = run_node(HARNESS, {"source": str(SOURCE)})
        self.assertEqual(
            result["atSubmit"],
            {
                "plain": {"loading": True, "busy": "true"},
                "intercepted": {"loading": False, "busy": None},
                "other": {"loading": False, "busy": None},
            },
        )
        self.assertEqual(result["afterRestore"], {"loading": False, "busy": None})
