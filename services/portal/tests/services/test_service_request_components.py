"""The service request form must use shared components for its visible controls."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast

from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[4]


class _TemplateFinding(Protocol):
    code: str
    severity: str
    exempted: bool


def _load_script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"_quality_gate_{name}", REPO_ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclasses need their defining module registered during execution.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ServiceRequestComponentGateTests(SimpleTestCase):
    def test_service_request_action_has_zero_template_blockers(self) -> None:
        module = _load_script("lint_template_components")
        scan = cast(Callable[[Path], list[_TemplateFinding]], module.scan_file)
        path = REPO_ROOT / "services/portal/templates/services/service_request_action.html"
        self.assertTrue(path.is_file())
        blockers = [finding.code for finding in scan(path) if finding.severity == "blocker" and not finding.exempted]
        self.assertEqual(blockers, [])
