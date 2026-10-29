"""The sample-data script seeds superusers with published passwords: it must refuse to run without DEBUG."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "setup_test_data.py"


class SetupTestDataGateTests(SimpleTestCase):
    @override_settings(DEBUG=False)
    def test_refuses_to_seed_without_debug(self) -> None:
        spec = importlib.util.spec_from_file_location("setup_test_data", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        with patch("django.setup"):
            spec.loader.exec_module(module)
        with (
            patch.object(module, "check_existing_data", return_value=False) as check_existing,
            patch.object(module, "create_test_data") as create,
            self.assertRaises(SystemExit),
        ):
            module.main()
        check_existing.assert_not_called()
        create.assert_not_called()
