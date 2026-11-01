"""Native source inspection finds real retained-routing dependencies and changes no service state."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from apps.provisioning.component_migration_inspection import collect_source_components
from apps.provisioning.component_migration_manifest import ComponentManifest
from apps.provisioning.virtualmin_security import connection_identity
from tests.virtualmin_lab.components.conftest import MixedSource

NATIVE_PROOF = r"""
import hashlib,importlib.util,json,subprocess,sys
from pathlib import Path
data=json.load(sys.stdin);request=data['request'];directory=Path(data['directory'])
spec=importlib.util.spec_from_file_location('source_inspection',directory/'praho-component-inspect.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
domain=Path('/etc/webmin/virtual-server/domains')/request['domain_id']
web=Path('/etc/apache2/sites-available')/(request['domain']+'.conf')
original_domain=domain.read_bytes();original_web=web.read_bytes()
shadow=hashlib.sha256(subprocess.check_output(['getent','shadow',request['owner']])).hexdigest()
evidence=module.inspect_source(request)
assert domain.read_bytes()==original_domain and web.read_bytes()==original_web,'Inspection changed native configuration'
assert hashlib.sha256(subprocess.check_output(['getent','shadow',request['owner']])).hexdigest()==shadow,'Inspection changed Unix authentication'
print(json.dumps(evidence,sort_keys=True))
"""


def test_native_inspection_reports_mail_routing_preparation_without_service_mutation(mixed_source: MixedSource) -> None:
    lab = mixed_source.lab
    directory = lab.exec("mktemp", "-d", "/var/lib/praho-inspect-contract.XXXXXXXX").strip()
    assert re.fullmatch(r"/var/lib/praho-inspect-contract\.[A-Za-z0-9]+", directory)
    helpers = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks/files"
    try:
        for name in (
            "praho-component-inspect.py",
            "praho-component-paths.py",
            "praho-component-mysql.py",
            "praho-component-cron-fence.py",
            "praho-component-capacity.py",
            "praho-component-default.py",
            "praho-apache-bindings.py",
            "praho-component-archive.py",
            "praho-account-name-neutral.py",
        ):
            copied = subprocess.run(  # noqa: S603 -- public code into the exact disposable fixture directory
                ["docker", "exec", "-i", lab.node.container, "tee", directory + "/" + name],  # noqa: S607
                input=(helpers / name).read_text(),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            assert copied.returncode == 0, "Could not install the native inspection helper"
        request = {
            "server_uuid": str(lab.server.pk),
            "connection_identity": connection_identity(lab.server),
            "domain_id": mixed_source.domain_id,
            "domain": mixed_source.domain,
            "owner": mixed_source.owner,
            "paths": [{"relative": "public_html", "purpose": "application"}],
            "databases": [],
        }
        result = subprocess.run(  # noqa: S603 -- disposable source, no credentials in the inspection request
            ["docker", "exec", "-i", lab.node.container, "python3", "-c", NATIVE_PROOF],  # noqa: S607
            input=json.dumps({"directory": directory, "request": request}),
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert lab.password not in result.stdout
        manifest = ComponentManifest.parse(json.loads(result.stdout))
        facts = manifest.as_json()
        assert facts["source"]["domain_id"] == mixed_source.domain_id
        assert facts["source"]["connection_identity"] == connection_identity(lab.server)
        assert manifest.selected_paths == ("public_html",)
        assert {"mail", "dns", "authentication", "mysql"} <= set(facts["retained"]["services"])
        assert "HTTP" in " ".join(facts["preparation"])
        assert "SPF" in " ".join(facts["preparation"])
        assert not any("callbacks" in item for item in facts["preparation"])
        remote = collect_source_components(lab.server, request)
        assert remote.authority_digest == manifest.authority_digest
    finally:
        lab.exec("rm", "-rf", "--", directory)
