"""Controller dependencies belong to Platform's runtime, including its background worker."""

import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_controller_is_platform_scoped_and_locked() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    groups = project["dependency-groups"]
    assert "ansible-core==2.20.6" in groups["platform"]
    assert not any("ansible" in item for item in groups["portal"])
    locked = tomllib.loads((ROOT / "uv.lock").read_text())
    assert any(package["name"] == "ansible-core" and package["version"] == "2.20.6" for package in locked["package"])


def test_runtime_images_and_native_units_provide_controller_paths() -> None:
    dockerfile = (ROOT / "deploy/platform/Dockerfile").read_text()
    runtime = dockerfile.rsplit("FROM ", 1)[1]
    assert "openssh-client" in runtime
    assert "COPY --from=builder /opt/praho-ansible/collections" in runtime
    for name in ("praho-platform", "praho-qcluster"):
        unit = (ROOT / f"deploy/ansible/roles/praho-native/templates/{name}.service.j2").read_text()
        assert "ANSIBLE_COLLECTIONS_PATH=/opt/praho-ansible/collections" in unit
        assert f"ANSIBLE_HOME=/run/{name}/ansible" in unit
        assert f"ANSIBLE_LOCAL_TEMP=/run/{name}/ansible/tmp" in unit
        assert f"RuntimeDirectory={name}" in unit and "RuntimeDirectoryMode=0700" in unit
        assert "ProtectHome=yes" in unit and "ProtectSystem=strict" in unit
    requirements = yaml.safe_load((ROOT / "services/platform/infrastructure/ansible/requirements.yml").read_text())
    assert {item["name"] for item in requirements["collections"]} == {"community.general", "ansible.posix"}
    assert all(item["version"][0].isdigit() for item in requirements["collections"])
