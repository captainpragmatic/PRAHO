"""The deploy form offers only the sizes sold in the chosen region, executed in the production controller."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from django.test import SimpleTestCase

SOURCE = Path(__file__).resolve().parents[2] / "static/js/alpine-components.js"

# ids arrive as numbers from json_script and as strings from x-model and restored drafts.
REGIONS = [
    {"id": 1, "name": "Helsinki", "provider_id": 7, "country_code": "fi", "normalized_code": "hel1", "city": "Helsinki"},
    {"id": 2, "name": "Ashburn", "provider_id": 7, "country_code": "us", "normalized_code": "ash1", "city": "Ashburn"},
    {"id": 3, "name": "Singapore", "provider_id": 7, "country_code": "sg", "normalized_code": "sin1", "city": "Sin"},
]
SIZES = [
    {"id": 10, "name": "CPX11", "provider_id": 7, "region_ids": [2]},
    {"id": 11, "name": "CX23", "provider_id": 7, "region_ids": [1]},
    {"id": 12, "name": "CPX22", "provider_id": 7, "region_ids": [1, 2]},
]

SCRIPT = """
const fs = require("fs");
const [source, regions, sizes, initial, steps] = process.argv.slice(1);
const nodes = {
  "regions-data": regions, "sizes-data": sizes, "providers-data": "[]", "deployment-form-data": initial,
};
global.window = {addEventListener: () => {}};
global.document = {
  addEventListener: (_, callback) => callback(),
  getElementById: (id) => (id in nodes ? {textContent: nodes[id]} : null),
};
global.fetch = async () => ({json: async () => ({hostname: "", fqdn: ""})});
const registry = {};
global.Alpine = {data: (name, factory) => { registry[name] = factory; }};
eval(fs.readFileSync(source, "utf8"));
const form = registry.deploymentForm();
const watchers = {};
form.$el = {dataset: {dnsZone: "nodes.example.com", hostnamePreviewUrl: "/preview/"}};
form.$watch = (name, callback) => { watchers[name] = callback; };
form.init();
const snapshot = () => ({
  sizes: form.filteredSizes.map((size) => size.name),
  nodeSize: form.nodeSize,
  canSubmit: Boolean(form.canSubmit),
  sizeHint: Boolean(form.showSizeHint),
  noSizes: Boolean(form.showNoSizesInRegion),
});
const out = [snapshot()];
for (const [field, value] of JSON.parse(steps)) {
  const previous = form[field];
  form[field] = value;
  if (watchers[field]) watchers[field](value, previous);
  out.push(snapshot());
}
process.stdout.write(JSON.stringify(out));
"""


def run_form(initial: dict[str, str], steps: list[tuple[str, str]] | None = None) -> list[dict[str, Any]]:
    result = subprocess.run(  # noqa: S603  # Fixed executable and local controller; no shell.
        [  # noqa: S607  # Fixed Node invocation.
            "node", "-e", SCRIPT, str(SOURCE), json.dumps(REGIONS), json.dumps(SIZES), json.dumps(initial),
            json.dumps(steps or []),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    snapshots: list[dict[str, Any]] = json.loads(result.stdout)
    return snapshots


class DeploymentFormSizesTests(SimpleTestCase):
    def test_only_sizes_sold_in_the_chosen_region_are_listed(self) -> None:
        hel1, ash = run_form({"provider": "7", "region": "1"}, [("region", "2")])
        self.assertEqual(hel1["sizes"], ["CX23", "CPX22"])
        self.assertEqual(ash["sizes"], ["CPX11", "CPX22"])

    def test_changing_region_drops_a_size_not_sold_there(self) -> None:
        _, chosen, moved = run_form({"provider": "7", "region": "1"}, [("nodeSize", "11"), ("region", "2")])
        self.assertTrue(chosen["canSubmit"])
        self.assertEqual(moved["nodeSize"], "")
        self.assertFalse(moved["canSubmit"])

    def test_changing_region_keeps_a_size_sold_in_both(self) -> None:
        *_, moved = run_form({"provider": "7", "region": "1"}, [("nodeSize", "12"), ("region", "2")])
        self.assertEqual(moved["nodeSize"], "12")
        self.assertTrue(moved["canSubmit"])

    def test_restored_draft_size_no_longer_offered_is_dropped(self) -> None:
        (restored,) = run_form({"provider": "7", "region": "1", "node_size": "10"})
        self.assertEqual(restored["nodeSize"], "")
        self.assertFalse(restored["canSubmit"])

    def test_empty_states_say_what_is_missing(self) -> None:
        (no_region,) = run_form({"provider": "7"})
        self.assertEqual(no_region["sizes"], [])
        self.assertTrue(no_region["sizeHint"])
        self.assertFalse(no_region["noSizes"])
        (nothing_sold,) = run_form({"provider": "7", "region": "3"})
        self.assertEqual(nothing_sold["sizes"], [])
        self.assertFalse(nothing_sold["sizeHint"])
        self.assertTrue(nothing_sold["noSizes"])
