"""A self-replacing control gets focus back after its own swap, whatever other requests do meanwhile (#821).

toggle_badge is disabled while its request runs (hx-disabled-elt), which drops focus to the body before htmx could
restore it, so ui-actions.js remembers the focused control per request and focuses the same-id replacement when that
request settles. Two toggles in flight at once, or an unrelated request settling first, must not lose or steal it.
A failed request swaps nothing and never settles, so its afterRequest gives focus back to the re-enabled control.
"""

from pathlib import Path

from django.test import SimpleTestCase

from tests.ui.node_harness import run_node

SOURCE = Path(__file__).resolve().parents[4] / "shared" / "ui" / "static" / "js" / "ui-actions.js"

HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const listeners = {};
const body = {id: "", focus() { document.activeElement = body; }};
const byId = {};
function control(id, keep) {
  const el = {
    id,
    hasAttribute(name) { return keep && name === "data-keep-focus"; },
    focus() { document.activeElement = el; },
  };
  return el;
}
const document = {
  activeElement: body,
  body,
  addEventListener(name, fn) { (listeners[name] = listeners[name] || []).push(fn); },
  getElementById(id) { return byId[id] || null; },
  querySelectorAll() { return []; },
};
const context = {console, Object, WeakMap, setTimeout, document, window: {addEventListener() {}}};
vm.runInNewContext(fs.readFileSync(input.source, "utf8"), context);
function fire(name, detail) { for (const fn of listeners[name] || []) fn({detail}); }
function swap(old) {
  // hx-disabled-elt blurred it; the response replaces it with a same-id copy.
  if (document.activeElement === old) document.activeElement = body;
  byId[old.id] = control(old.id, true);
  return byId[old.id];
}

const results = {};
// A: toggle A is focused and posts. B: an unrelated, unfocused request starts and settles first.
let a = control("toggle-a", true); byId[a.id] = a; a.focus();
const xhrA = {}, xhrOther = {};
fire("htmx:beforeRequest", {elt: a, xhr: xhrA});
const other = control("search", false);
fire("htmx:beforeRequest", {elt: other, xhr: xhrOther});
a = swap(a);
fire("htmx:afterSettle", {xhr: xhrOther});
results.otherSettleLeavesFocusAlone = document.activeElement === body;
fire("htmx:afterSettle", {xhr: xhrA});
results.ownSettleRestoresFocus = document.activeElement === a;

// Two toggles in flight: C posts, the user moves to D, which posts too. C's answer lands while D is focused (it
// must not take focus back), then D's answer lands (it gets focus back).
let c = control("toggle-c", true); byId[c.id] = c; c.focus();
const xhrC = {}, xhrD = {};
fire("htmx:beforeRequest", {elt: c, xhr: xhrC});
let d = control("toggle-d", true); byId[d.id] = d; d.focus();
fire("htmx:beforeRequest", {elt: d, xhr: xhrD});
c = swap(c);
fire("htmx:afterSettle", {xhr: xhrC});
results.otherToggleDoesNotStealFocus = document.activeElement === d;
d = swap(d);
fire("htmx:afterSettle", {xhr: xhrD});
results.laterFocusedToggleKeepsFocus = document.activeElement === d;

// A failed request (400, 403, a network error) swaps nothing, so no settle follows: htmx re-enables the same element
// and fires afterRequest; focus goes back to it. A later settle of that request has nothing left to restore.
function blurred(el) { if (document.activeElement === el) document.activeElement = body; }
let e = control("toggle-e", true); byId[e.id] = e; e.focus();
const xhrE = {};
fire("htmx:beforeRequest", {elt: e, xhr: xhrE});
blurred(e);
fire("htmx:afterRequest", {elt: e, xhr: xhrE, successful: false, failed: true});
results.failedResponseReturnsFocus = document.activeElement === e;
let f = control("toggle-f", true); byId[f.id] = f; f.focus();
const xhrF = {};
fire("htmx:beforeRequest", {elt: f, xhr: xhrF});
blurred(f);
fire("htmx:afterRequest", {elt: f, xhr: xhrF, successful: false});  // sendError/abort/timeout carry no `failed`
results.sendErrorReturnsFocus = document.activeElement === f;
// A successful request is left to its settle: afterRequest does not restore early or consume it.
let g = control("toggle-g", true); byId[g.id] = g; g.focus();
const xhrG = {};
fire("htmx:beforeRequest", {elt: g, xhr: xhrG});
g = swap(g);
fire("htmx:afterRequest", {elt: g, xhr: xhrG, successful: true, failed: false});
results.successWaitsForSettle = document.activeElement === body;
fire("htmx:afterSettle", {xhr: xhrG});
results.successSettleRestores = document.activeElement === g;
process.stdout.write(JSON.stringify(results));
"""


class KeepFocusTests(SimpleTestCase):
    def test_focus_is_restored_by_its_own_request_only(self) -> None:
        self.assertEqual(
            run_node(HARNESS, {"source": str(SOURCE)}),
            {
                "otherSettleLeavesFocusAlone": True,
                "ownSettleRestoresFocus": True,
                "otherToggleDoesNotStealFocus": True,
                "laterFocusedToggleKeepsFocus": True,
                "failedResponseReturnsFocus": True,
                "sendErrorReturnsFocus": True,
                "successWaitsForSettle": True,
                "successSettleRestores": True,
            },
        )
