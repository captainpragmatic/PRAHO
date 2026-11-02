"""The settings buttons' busy labels come from data-* attributes, read by component getters.

The Save button's label was an x-text expression with two translations spliced into JS strings
('{% trans "Saving…" %}'): an apostrophe in a Romanian translation would end the string and break the expression.
The labels are data-* attributes on the component root now, and the buttons are the button component.
"""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase

from tests.ui.node_harness import run_node

SOURCE = Path(__file__).resolve().parents[2] / "static" / "js" / "alpine-components.js"

HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const registry = {};
const context = {
  console, Object, JSON,
  document: {addEventListener(name, fn) { if (name === "alpine:init") fn(); }, querySelector() { return null; }},
  window: {addEventListener() {}},
  Alpine: {data(name, factory) { registry[name] = factory; }},
};
vm.runInNewContext(fs.readFileSync(input.source, "utf8"), context);
const labels = {saveLabel: "Salvează", savingLabel: "Se salvează…", testLabel: "Testează", testingLabel: "Se testează…",
  unsavedLabel: "modificări nesalvate", configuredLabel: "●  Configurat", notConfiguredLabel: "○  Neconfigurat"};
const form = registry.settingsForm("/save/"); form.$root = {dataset: labels};
const test = registry.settingsIntegrationTest(); test.$root = {dataset: labels};
const row = registry.settingsSecretRow(true); row.$root = {dataset: labels};
const out = {};
form.dirty = {a: true, b: true}; out.unsaved = form.unsavedLabel;
out.configured = row.configuredLabel; row.configured = false; out.notConfigured = row.configuredLabel; row.configured = true;
out.save = form.saveLabel; form.saving = true; out.saving = form.saveLabel;
out.test = test.testLabel; test.testing = true; out.testing = test.testLabel;
out.emptyDisabled = row.saveDisabled; row.secret = " key "; out.filledDisabled = row.saveDisabled;
row.busy = true; out.busyDisabled = row.saveDisabled;
process.stdout.write(JSON.stringify(out));
"""


class SettingsButtonLabelTests(SimpleTestCase):
    def test_labels_and_disabled_state_follow_the_component_state(self) -> None:
        result = run_node(HARNESS, {"source": str(SOURCE)})
        self.assertEqual(
            result,
            {
                "unsaved": "2 modificări nesalvate",
                "configured": "●  Configurat",
                "notConfigured": "○  Neconfigurat",
                "save": "Salvează",
                "saving": "Se salvează…",
                "test": "Testează",
                "testing": "Se testează…",
                "emptyDisabled": True,
                "filledDisabled": False,
                "busyDisabled": True,
            },
        )
