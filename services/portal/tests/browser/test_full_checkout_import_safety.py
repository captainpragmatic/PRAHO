"""The opt-in full checkout settings cannot change normal Portal configuration."""

import importlib
import os
from unittest.mock import patch


def test_full_checkout_settings_import_without_opt_in_or_starting_a_process():
    from config.settings import dev  # noqa: PLC0415

    original = dev.PLATFORM_API_BASE_URL
    with (
        patch.dict(os.environ, {"HOSTING_CHECKOUT_FULL": "0"}),
        patch("subprocess.Popen", side_effect=AssertionError("Unexpected process")) as spawn,
    ):
        module = importlib.import_module("tests.browser.full_checkout_settings")
        assert module.PLATFORM_API_BASE_URL.startswith("http://127.0.0.1:")
        assert original == dev.PLATFORM_API_BASE_URL
        spawn.assert_not_called()
