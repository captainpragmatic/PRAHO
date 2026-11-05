"""Select independent native topologies without skipping or duplicating acceptance cases."""

import pytest

from scripts.run_native_acceptance import PROFILES, native_profile


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if not any(item.path.name == "test_native_acceptance.py" for item in items):
        return
    try:
        topology = PROFILES[native_profile()][0]
    except ValueError as error:
        raise pytest.UsageError(str(error)) from error
    if topology is None:
        return
    selected, deselected = [], []
    for item in items:
        parameters = getattr(getattr(item, "callspec", None), "params", {})
        if item.path.name == "test_native_acceptance.py" and parameters.get("lab") != topology:
            deselected.append(item)
        else:
            selected.append(item)
    items[:] = selected
    config.hook.pytest_deselected(items=deselected)
