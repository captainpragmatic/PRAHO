"""Exercise the rendered modal defaults and actions without a browser."""

from __future__ import annotations

from pathlib import Path

from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.utils import translation

from tests.ui.node_harness import Markup, dataset, run_node

ROOT = Path(__file__).resolve().parents[4]

HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const components = {};
const context = {
  document: {addEventListener(name, fn) { if (name === "alpine:init") fn(); }},
  Alpine: {data(name, factory) { components[name] = factory; }}
};
vm.runInNewContext(input.source, context);
const modal = components.dangerousActionModal();
modal.$root = {dataset: input.defaults};
const states = [];
let confirmed = "";
function state() {
  return {
    show: modal.show, title: modal.title, message: modal.message,
    phrase: modal.confirmText, value: modal.userInput, valid: modal.isValid, confirmed
  };
}
modal.onConfirmRequest({detail: {action() { confirmed = "default"; }}});
states.push(state());
modal.userInput = "I understand";
modal.submitIfValid();
states.push(state());
modal.userInput = input.defaults.defaultConfirmText;
modal.submitIfValid();
states.push(state());
modal.open({
  title: "Titlu ales", message: "<strong>Mesaj ales</strong>",
  confirmText: "CONFIRMĂ ALES", action() { confirmed = "override"; }
});
states.push(state());
modal.userInput = "CONFIRMĂ ALES";
modal.confirm();
states.push(state());
modal.open({});
states.push(state());
process.stdout.write(JSON.stringify({states}));
"""


class DangerousActionModalTests(SimpleTestCase):
    def test_romanian_defaults_and_caller_overrides_survive_opening(self) -> None:
        with translation.override("ro"):
            markup = Markup(render_to_string("components/dangerous_action_modal.html"))
        attributes = markup.find("x-data", "dangerousActionModal")
        self.assertEqual(attributes["@confirm-dangerous-action.window"], "onConfirmRequest($event)")
        self.assertEqual(markup.find("id", "dangerous-action-confirmation")["x-model"], "userInput")
        self.assertEqual(markup.find("@click", "confirm()")[":disabled"], "isInvalid")
        self.assertEqual(markup.find("id", "dangerous-action-confirmation")["@keyup.enter"], "submitIfValid()")
        defaults = dataset(attributes)
        self.assertEqual(defaults["defaultTitle"], "Acțiune periculoasă")
        self.assertEqual(defaults["defaultMessage"], "Această acțiune nu poate fi anulată.")
        self.assertEqual(defaults["defaultConfirmText"], "Sunt sigur că vreau să fac acest lucru!")
        output = run_node(
            HARNESS,
            {
                "source": (ROOT / "shared/ui/static/js/alpine-shared-components.js").read_text(encoding="utf-8"),
                "defaults": defaults,
            },
        )
        opened = {
            "show": True,
            "title": defaults["defaultTitle"],
            "message": defaults["defaultMessage"],
            "phrase": defaults["defaultConfirmText"],
            "value": "",
            "valid": False,
            "confirmed": "",
        }
        closed = {
            **opened,
            "show": False,
            "confirmed": "default",
        }
        overridden = {
            **opened,
            "title": "Titlu ales",
            "message": "<strong>Mesaj ales</strong>",
            "phrase": "CONFIRMĂ ALES",
            "confirmed": "default",
        }
        self.assertEqual(
            output["states"],
            [
                opened,
                {**opened, "value": "I understand"},
                closed,
                overridden,
                {**overridden, "show": False, "confirmed": "override"},
                {**opened, "confirmed": "override"},
            ],
        )
