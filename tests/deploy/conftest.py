"""Select independent native topologies without skipping or duplicating acceptance cases."""

import pytest

from scripts.run_native_acceptance import PROFILES, SHARD_CASES, case_key, native_profile


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if not any(item.path.name == "test_native_acceptance.py" for item in items):
        return
    try:
        profile = native_profile()
    except ValueError as error:
        raise pytest.UsageError(str(error)) from error
    topology = PROFILES[profile][0]
    if topology is None:
        return
    cases = SHARD_CASES.get(profile)
    selected, deselected = [], []
    for item in items:
        parameters = getattr(getattr(item, "callspec", None), "params", {})
        native = item.path.name == "test_native_acceptance.py"
        outside_topology = parameters.get("lab") != topology
        outside_shard = (
            cases is not None and case_key(getattr(item, "originalname", item.name), parameters) not in cases
        )
        if native and (outside_topology or outside_shard):
            deselected.append(item)
        else:
            selected.append(item)
    items[:] = selected
    config.hook.pytest_deselected(items=deselected)
