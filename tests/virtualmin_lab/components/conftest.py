"""Disposable mixed-service domains on the opt-in imported source; never managed-node hardening."""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

import django
import pytest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.lab")
django.setup()

from apps.provisioning.management.commands._virtualmin_lab import (  # noqa: E402
    COMPONENT_SOURCE,
    lab_transport,
    load_state,
    refuse_unless_lab_settings,
)
from apps.provisioning.virtualmin_gateway import VirtualminConfig, listing_attribute  # noqa: E402
from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: E402
from apps.provisioning.virtualmin_service import create_domain_params  # noqa: E402
from tests.virtualmin_lab.components.site_observation import observe_target_site  # noqa: E402
from tests.virtualmin_lab.contract.harness import (  # noqa: E402
    Lab,
    Recorder,
    RecordingGateway,
    assert_accepted,
)


@dataclass(frozen=True)
class MixedSource:
    lab: Lab
    domain: str
    owner: str
    domain_id: str
    cleanup_callbacks: list[Callable[[], None]] = field(default_factory=list, compare=False)


@pytest.fixture
def native_target_site_observation(mixed_source: MixedSource) -> Iterator[None]:
    with observe_target_site(mixed_source.domain):
        yield


@pytest.fixture
def mixed_source() -> Iterator[MixedSource]:
    refuse_unless_lab_settings()
    server = VirtualminServer.objects.get(hostname=COMPONENT_SOURCE.server_hostname)
    assert getattr(server, "node_deployment", None) is None, "Mixed source must remain a real import"
    suffix = secrets.token_hex(5)
    domain, owner = "component-contract-" + suffix + ".praho.test", "comp" + suffix
    password = "Qz9" + secrets.token_hex(12)
    with lab_transport(load_state()):
        lab = Lab(
            RecordingGateway(VirtualminConfig(server=server)),
            COMPONENT_SOURCE,
            server,
            Recorder(version="8.3.0", directory=None),
            password=password,
        )
        assert not lab.domain_exists(domain)
        parameters = create_domain_params(
            domain=domain,
            username=owner,
            password=password,
            template="Default Settings",
            recovery_seed="component-contract-fixture",
            disk_quota_mb=1024,
            bandwidth_quota_mb=10240,
        )
        parameters.update({"mail": "", "dns": ""})
        assert_accepted(lab.quiet("create-domain", parameters, timeout_seconds=180))
        values = lab.domain_values(domain)
        domain_id = str(listing_attribute(values, "ID"))
        assert domain_id.isdecimal() and listing_attribute(values, "Username") == owner
        assert {"mail", "dns", "mysql", "web"} <= set(str(listing_attribute(values, "Features")).split())
        fixture = MixedSource(lab, domain, owner, domain_id)
        try:
            yield fixture
        finally:
            current = lab.domain_values(domain)
            assert str(listing_attribute(current, "ID")) == domain_id
            assert listing_attribute(current, "Username") == owner
            lab.exec("test", "!", "-e", "/etc/apache2/conf-enabled/praho-z-component-" + domain_id + ".conf")
            lab.remove_domain(domain)
            for cleanup in fixture.cleanup_callbacks:
                cleanup()
