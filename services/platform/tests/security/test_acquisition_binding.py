"""App coverage hashes must be exact renders of the deployed acquisition template."""

import json
import os
from pathlib import Path

from django.test import SimpleTestCase
from jinja2 import Environment

from apps.security import replication


class CoverageAcquisitionBindingTests(SimpleTestCase):
    def test_shareable_names_are_exactly_the_pinned_hostile_scenario_candidates(self) -> None:
        root = Path(__file__).resolve().parents[4]
        path = Path(os.environ.get("CROWDSEC_ARTIFACT_LOCK", root / "deploy/crowdsec/artifacts.lock.json"))
        manifest = json.loads(path.read_text())
        self.assertEqual(replication.SCENARIOS, frozenset(manifest["hub"]["replication_candidates"]))

    def test_each_accepted_acquisition_document_matches_the_actual_role_template(self) -> None:
        root = Path(__file__).resolve().parents[4]
        path = Path(
            os.environ.get(
                "CROWDSEC_ROLE_ACQUISITION_TEMPLATE", root / "deploy/ansible/roles/crowdsec/templates/acquis.yaml.j2"
            )
        )
        template = Environment(trim_blocks=True, keep_trailing_newline=True, autoescape=False).from_string(  # noqa: S701 -- YAML must match Ansible's text rendering byte for byte.
            path.read_text()
        )
        for kind, mode, expected in (
            ("node", "file", replication.NODE_FILE_ACQUISITION),
            ("node", "journalctl", replication.NODE_JOURNAL_ACQUISITION),
            ("portal", "file", replication.PORTAL_FILE_ACQUISITION),
            ("portal", "journalctl", replication.PORTAL_JOURNAL_ACQUISITION),
        ):
            with self.subTest(kind=kind, mode=mode):
                self.assertEqual(template.render(crowdsec_host_kind=kind, crowdsec_ssh_acquisition=mode), expected)
