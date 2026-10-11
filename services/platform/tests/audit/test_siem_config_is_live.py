"""Every SIEM setting the code accepts is one it reads.

The SIEM transport (buffering, retries, filters, the file sink under SIEM_LOG_DIR) was removed in
#399, but its configuration stayed: operators could set values that did nothing. ADR-0043 §6
keeps two paths, log formatting and `audit_compliance export-siem --output`, which read only the
format and the CEF/LEEF vendor fields.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import re
from pathlib import Path

from django.test import SimpleTestCase

from apps.audit import siem
from apps.audit.siem import SIEMConfig

PLATFORM = Path(__file__).resolve().parents[2]
APPS = PLATFORM / "apps"
SETTINGS = PLATFORM / "config" / "settings"


def _app_sources_without_the_config_plumbing() -> str:
    sources = []
    plumbing = inspect.getsource(SIEMConfig) + inspect.getsource(siem.get_siem_config)
    for path in APPS.rglob("*.py"):
        text = path.read_text()
        if path.name == "siem.py" and path.parent.name == "audit":
            text = text.replace(plumbing, "")
        sources.append(text)
    return "\n".join(sources)


class SIEMConfigIsLiveTests(SimpleTestCase):
    def test_every_config_field_is_read_by_the_code(self) -> None:
        sources = _app_sources_without_the_config_plumbing()
        unread = [
            field.name
            for field in dataclasses.fields(SIEMConfig)
            if not re.search(rf"\bconfig\.{field.name}\b", sources)
        ]
        self.assertEqual(unread, [], "SIEMConfig fields that nothing reads")

    def test_every_production_setting_is_read_by_get_siem_config(self) -> None:
        tree = ast.parse((SETTINGS / "prod.py").read_text())
        [siem_config] = [
            node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "SIEM_CONFIG" for target in node.targets)
        ]
        assert isinstance(siem_config, ast.Dict)
        configured = {key.value for key in siem_config.keys if isinstance(key, ast.Constant)}
        read = set(re.findall(r'siem_settings\.get\("([A-Z_]+)"', inspect.getsource(siem.get_siem_config)))
        self.assertEqual(configured - read, set(), "SIEM_CONFIG keys that get_siem_config never reads")

    def test_no_settings_module_defines_a_siem_log_directory(self) -> None:
        for path in SETTINGS.glob("*.py"):
            with self.subTest(settings=path.name):
                assigned = {
                    target.id
                    for node in ast.walk(ast.parse(path.read_text()))
                    if isinstance(node, ast.Assign)
                    for target in node.targets
                    if isinstance(target, ast.Name)
                }
                self.assertNotIn("SIEM_LOG_DIR", assigned)
