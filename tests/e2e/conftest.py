"""
E2E Test Configuration for PRAHO Platform

Centralized configuration for all end-to-end tests using pytest-playwright.
This file customizes browser launch args based on the runtime environment.
"""

import os
import sys

import pytest


def _get_chromium_args() -> list[str]:
    """
    Build Chromium launch arguments based on the runtime environment.

    On CI/Linux containers: aggressive flags for headless stability.
    On macOS dev: minimal flags to avoid browser crashes.
    """
    # Common safe args for all environments
    args = [
        "--disable-dev-shm-usage",
        "--disable-gpu",
    ]

    # Container/CI-only args (Linux) - these crash Chromium on macOS
    if os.environ.get("CI") or sys.platform == "linux":
        args.extend([
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--single-process",
            "--no-zygote",
            "--disable-software-rasterizer",
        ])

    return args


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args):
    """
    Configure browser launch arguments based on the runtime environment.
    """
    return {
        **browser_type_launch_args,
        "args": _get_chromium_args(),
    }


def pytest_configure(config):
    """Register custom markers for E2E tests."""
    config.addinivalue_line("markers", "e2e: end-to-end test")
