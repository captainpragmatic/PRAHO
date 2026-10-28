"""Native account-name web isolation, retained TLS and the real held-restore boundary."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
from django.conf import settings

from apps.common.types import Retriability, retriability_of
from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.account_name_node import (
    ensure_account_name_neutral,
    prepare_account_name_neutral,
    retire_account_name_neutral,
)
from apps.provisioning.migration_barrier import BarrierRecord, barrier_variables, run_barrier
from apps.provisioning.migration_target_hold import (
    capture_backup_owner_shadow,
    cleanup_held_target,
    held_pair_variables,
    run_held_target_node,
)
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import migration_backup_params
from apps.provisioning.virtualmin_pair_restore import run_pair_step
from tests.virtualmin_lab.contract.harness import Lab, assert_accepted

_REQUEST = r"""
import json,pathlib,re,subprocess,sys,tempfile
name,host,scheme,path,anchor,options=sys.argv[1:];options=json.loads(options)
address=options.get('address','127.0.0.1');resolved='['+address+']' if ':' in address else address
if options.get('hostless'):
    result=subprocess.run(['openssl','s_client','-connect',resolved+':443','-servername',name,
        '-verify_hostname',name,'-verify_return_error','-CAfile',anchor,'-quiet','-ign_eof'],
        input='GET /'+path+' HTTP/1.0\r\nConnection: close\r\n\r\n',capture_output=True,text=True,timeout=20)
    headers,_,body=result.stdout.replace('\r\n','\n').partition('\n\n')
    match=re.match(r'HTTP/1\.[01] ([0-9]{3})',headers);code=match[1] if match else ''
else:
    port='443' if scheme=='https' else '80'
    args=['curl','--noproxy','*','--connect-timeout','3','--max-time','15','-sS',
          '--resolve',name+':'+port+':'+resolved,'--header','Host: '+host,'--write-out','%{http_code}']
    if scheme=='https':args+=['--cacert',anchor]
    if options.get('absolute'):args+=['--request-target',options['absolute']]
    with tempfile.TemporaryDirectory(prefix='praho-neutral-response-') as scratch:
        header_file=pathlib.Path(scratch)/'headers'
        result=subprocess.run(args+['--dump-header',str(header_file),scheme+'://'+name+':'+port+'/'+path],
                              capture_output=True,text=True)
        headers=header_file.read_text() if header_file.exists() else ''
    code=result.stdout[-3:];body=result.stdout[:-3]
print(json.dumps({'rc':result.returncode,'code':code,'body':body,
                  'cookie':'set-cookie:' in headers.lower(),'location':'location:' in headers.lower()}))
"""

_APACHE_MANIFEST = r"""
import hashlib,json,os,pathlib,stat
result={}
for path in pathlib.Path('/etc/apache2').rglob('*'):
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode):value=['link',os.readlink(path)]
    elif stat.S_ISREG(info.st_mode):value=['file',hashlib.sha256(path.read_bytes()).hexdigest()]
    else:continue
    result[str(path)]=value+[stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid]
print(json.dumps(result))
"""

_NATIVE_TLS_PATHS = r"""
import json,pathlib,re,shlex,sys
name=sys.argv[1]
for path in pathlib.Path('/etc/apache2/sites-enabled').glob('*.conf'):
    for ports,body in re.findall(r'<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>',path.read_text(),re.S|re.I):
        values={}
        for line in body.splitlines():
            parts=shlex.split(line,comments=True)
            if len(parts)>1:values[parts[0].lower()]=parts[1]
        if values.get('servername')==name and any(port.endswith(':443') for port in ports.split()):
            print(json.dumps({'certificate':values['sslcertificatefile'],'key':values['sslcertificatekeyfile']}))
            raise SystemExit(0)
raise SystemExit(1)
"""

_CLEANUP_GUARDS = r"""
import hashlib,pathlib,shutil,sys
zone,name,probe=sys.argv[1:]
for kind,value in (('10-name',name),('20-zone',zone)):
    (pathlib.Path('/etc/apache2/conf-enabled')/('praho-neutral-'+kind+'-'+hashlib.sha256(value.encode()).hexdigest()+'.conf')).unlink(missing_ok=True)
directory=pathlib.Path('/var/lib/praho/account-name-neutral/names')/name
if directory.exists():shutil.rmtree(directory)
if pathlib.Path(probe).exists():shutil.rmtree(probe)
"""

_REFRESH_BINDINGS = r"""
import importlib.util
spec=importlib.util.spec_from_file_location('bindings','/var/lib/praho/apache-bindings/library.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
policy=module.ApacheBindings()
with policy.transaction():
    policy.refresh();policy.reload()
"""

_TENANT_VARIANTS = (
    ("", "probe.php"),
    ('ErrorDocument 404 "TENANT-ERROR"\n', "missing"),
    ("Redirect 302 / https://preview-escape.invalid/\n", "probe.php"),
    ('<If "true">\nRedirect 302 / https://preview-escape.invalid/\n</If>\n', "probe.php"),
    ('<If "true">\nErrorDocument 404 "TENANT-IF-ERROR"\n</If>\n', "missing"),
    ("ErrorDocument 404 /probe.php\n", "missing"),
    (
        "RewriteEngine On\nRewriteOptions IgnoreInherit\nRewriteRule ^rewrite-escape$ probe.php [END]\n",
        "rewrite-escape",
    ),
    ('Header always set Set-Cookie "preview_probe=tenant; Path=/"\n', "probe.php"),
    ('<If "true">\nHeader always set Set-Cookie "preview_probe=tenant; Path=/"\n</If>\n', "probe.php"),
)


@dataclass
class NativeNeutralCase:
    lab: Lab
    operation: UUID = field(default_factory=uuid4)
    certificate: str = ""
    child_home: str = ""
    domain_id: str = ""
    held: VirtualminMigration | None = None

    @property
    def zone(self) -> str:
        return f"neutral-{self.operation.hex[:8]}.praho.test"

    @property
    def name(self) -> str:
        return f"{self.operation.hex[:8]}.{self.zone}"

    @property
    def parent(self) -> str:
        return f"neutral-parent-{self.operation.hex[:8]}.praho.test"

    @property
    def owner(self) -> str:
        return "ng" + self.operation.hex[:8]

    @property
    def archive(self) -> str:
        return f"migration_{self.operation}.tar.gz"

    @property
    def private(self) -> str:
        return f"/var/lib/praho/neutral-probes/{self.operation}"

    @property
    def manifest(self) -> str:
        return f"/var/lib/praho/account-name-neutral/names/{self.name}/state.json"

    def ensure(self, fingerprint: str | None = None) -> str:
        result = ensure_account_name_neutral(
            self.lab.server,
            zone=self.zone,
            name=self.name,
            customer_user=self.owner,
            expected_certificate_sha256=fingerprint,
        )
        assert result.is_ok(), result.unwrap_err() if result.is_err() else ""
        return result.unwrap()

    def metadata(self) -> dict[str, Any]:
        return json.loads(
            self.lab.exec(
                "python3", "-c", "import pathlib,sys;print(pathlib.Path(sys.argv[1]).read_text())", self.manifest
            )
        )

    def copied_certificate(self) -> str:
        return self.lab.exec(
            "python3",
            "-c",
            'import pathlib,sys;print(next((pathlib.Path(sys.argv[1]).parent/"versions").glob("*/chain.pem")))',
            self.manifest,
        ).strip()

    def tenant_write(self, path: str, value: str) -> None:
        self.lab.exec(
            "runuser",
            "-u",
            self.owner,
            "--",
            "python3",
            "-c",
            f"from pathlib import Path;Path({path!r}).write_text({value!r})",
        )

    def native(self, program: str, domain: str, *, cascade: bool = False) -> None:
        assert_accepted(
            self.lab.quiet(program, {"domain": domain, **({"subservers": ""} if cascade else {})}, timeout_seconds=180)
        )

    def response(
        self,
        *,
        host: str | None = None,
        scheme: str = "http",
        path: str = "probe.php",
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return json.loads(
            self.lab.exec(
                "python3",
                "-c",
                _REQUEST,
                self.name,
                host or self.name,
                scheme,
                path,
                self.certificate,
                json.dumps(options or {}),
            )
        )

    def neutral(
        self,
        *,
        host: str | None = None,
        scheme: str = "http",
        path: str = "probe.php",
        options: dict[str, Any] | None = None,
    ) -> None:
        response = self.response(host=host, scheme=scheme, path=path, options=options)
        assert response == {"rc": 0, "code": "404", "body": "Not Found", "cookie": False, "location": False}

    def parent_response(self, *, held: bool = False) -> None:
        result = json.loads(
            self.lab.exec("python3", "-c", _REQUEST, self.parent, self.parent, "http", "probe.txt", "", "{}")
        )
        assert result["rc"] == 0
        assert result["code"] == ("503" if held else "200")
        assert result["body"] == ("Restore in progress" if held else "PARENT-UNAFFECTED")
        assert not result["cookie"]

    def hold(self) -> None:
        self.domain_id = self.lab.exec("virtualmin", "list-domains", "--domain", self.parent, "--id-only").strip()
        capture_backup_owner_shadow(
            self.lab.server,
            domain=self.parent,
            owner=self.owner,
            domain_id=self.domain_id,
            archive_name=self.archive,
            operation_id=self.operation,
        )
        assert_accepted(
            self.lab.quiet(
                "backup-domain", {"domain": self.parent, **migration_backup_params(self.archive)}, timeout_seconds=600
            )
        )
        checksum = self.lab.exec("sha256sum", "/var/lib/praho-transfer/" + self.archive).split()[0]
        self.native("disable-domain", self.parent, cascade=True)
        self.held = cast(
            VirtualminMigration,
            SimpleNamespace(
                pk=self.operation,
                account=SimpleNamespace(domain=self.parent, virtualmin_username=self.owner),
                target_server=self.lab.server,
                pre_migration_snapshot={"status": "active"},
                barrier_state={
                    "target_domain_id": self.domain_id,
                    "held_archives": [{"archive_name": self.archive, "checksum_sha256": checksum}],
                },
            ),
        )
        run_held_target_node(self.held, "stage")
        restored = run_pair_step(
            self.lab.server,
            {
                **held_pair_variables(self.held),
                "pair_action": "restore",
                "pair_recovery": True,
                "pair_base_archive": self.archive,
                "pair_base_sha": checksum,
            },
            token=str(self.operation),
            domain_id=self.domain_id,
            timeout_seconds=1380,
        )
        assert restored.is_ok(), restored.unwrap_err() if restored.is_err() else ""
        assert restored.unwrap().outcome == "ok" and restored.unwrap().barrier_broken() is None

    def release(self) -> None:
        assert self.held is not None
        released = run_pair_step(
            self.lab.server,
            {**held_pair_variables(self.held), "pair_action": "release"},
            token=str(self.operation),
            domain_id=self.domain_id,
            timeout_seconds=180,
        )
        assert released.is_ok() and released.unwrap().outcome == "released"
        cleanup_held_target(self.held)
        self.held = None

    def source_barrier_roundtrip(self) -> None:
        """Exercise the source consumer of the same private named-guard proof."""
        identity = str(uuid4())
        domain_id = self.lab.exec("virtualmin", "list-domains", "--domain", self.parent, "--id-only").strip()
        recorded = run_barrier(
            self.lab.server,
            barrier_variables("record", domain=self.parent, domain_id=domain_id, token=identity).unwrap(),
        ).unwrap()
        assert recorded.ok, recorded.reason
        record = BarrierRecord.from_state(recorded.payload).unwrap()
        try:
            applied = run_barrier(
                self.lab.server,
                barrier_variables(
                    "apply", domain=self.parent, domain_id=domain_id, token=identity, record=record
                ).unwrap(),
            ).unwrap()
            assert applied.ok, applied.reason
            self.neutral()
            self.neutral(scheme="https")
        finally:
            released = run_barrier(
                self.lab.server,
                barrier_variables(
                    "release", domain=self.parent, domain_id=domain_id, token=identity, record=record
                ).unwrap(),
            ).unwrap()
            assert released.ok, released.reason
            # The fixture has no later controller RPCs; retain no saved test cron.
            self.lab.exec("rm", "-f", "--", f"/var/lib/praho/migration/migration-{domain_id}.{identity}.crontab")

    def rotate_to_full_chain(self) -> str:
        """Generate all private material locally; trust only its root when checking served intermediates."""
        self.lab.exec("install", "-d", "-m", "0700", self.private)
        self.lab.exec(
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "30",
            "-subj",
            "/CN=Neutral Test Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
            self.private + "/root.key",
            "-out",
            self.private + "/root.pem",
        )
        for label, subject, extensions, issuer, serial in (
            (
                "intermediate",
                "/CN=Neutral Test Intermediate",
                "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
                "root",
                "2",
            ),
            (
                "leaf",
                "/CN=" + self.name,
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:"
                + self.name
                + ",DNS:*."
                + self.name
                + "\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
                "intermediate",
                "3",
            ),
        ):
            prefix = self.private + "/" + label
            self.lab.exec(
                "openssl",
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-subj",
                subject,
                "-keyout",
                prefix + ".key",
                "-out",
                prefix + ".csr",
            )
            self.lab.exec(
                "python3", "-c", f"from pathlib import Path;Path({prefix + '.ext'!r}).write_text({extensions!r})"
            )
            self.lab.exec(
                "openssl",
                "x509",
                "-req",
                "-in",
                prefix + ".csr",
                "-CA",
                self.private + "/" + issuer + ".pem",
                "-CAkey",
                self.private + "/" + issuer + ".key",
                "-set_serial",
                serial,
                "-days",
                "30",
                "-extfile",
                prefix + ".ext",
                "-out",
                prefix + ".pem",
            )
        native = json.loads(self.lab.exec("python3", "-c", _NATIVE_TLS_PATHS, self.name))
        self.lab.exec(
            "python3",
            "-c",
            'from pathlib import Path;import sys;p=Path(sys.argv[1]);Path(sys.argv[2]).write_bytes(b"".join((p/(n+".pem")).read_bytes() for n in ("leaf","intermediate","root")));Path(sys.argv[3]).write_bytes((p/"leaf.key").read_bytes())',
            self.private,
            native["certificate"],
            native["key"],
        )
        self.lab.exec("apache2ctl", "configtest")
        self.lab.exec("apache2ctl", "graceful")
        return self.lab.exec(
            "python3",
            "-c",
            "import hashlib,pathlib,ssl,sys;print(hashlib.sha256(ssl.PEM_cert_to_DER_cert(pathlib.Path(sys.argv[1]).read_text())).hexdigest())",
            self.private + "/leaf.pem",
        ).strip()


@pytest.fixture
def neutral_case(lab: Lab) -> Any:
    case = NativeNeutralCase(lab)
    default = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-default-site.conf"
    temporary_directory = lab.exec("mktemp", "-d").strip()
    temporary = temporary_directory + "/default.conf"
    docker = shutil.which("docker")
    assert docker is not None
    subprocess.run(  # noqa: S603  # Fixed local lab container and shipped asset inside its root-created temporary directory.
        [docker, "cp", str(default), f"{lab.node.container}:{temporary}"], check=True, capture_output=True, timeout=60
    )
    lab.exec("install", "-d", "-o", "root", "-g", "root", "-m", "0755", "/var/www/praho-default")
    lab.exec(
        "install",
        "-o",
        "root",
        "-g",
        "root",
        "-m",
        "0644",
        temporary,
        "/etc/apache2/conf-enabled/praho-default-site.conf",
    )
    lab.exec("rm", "--", temporary)
    lab.exec("rmdir", "--", temporary_directory)
    lab.exec("apache2ctl", "configtest")
    lab.exec("apache2ctl", "graceful")
    # The fixed shared binding/default policy is a shipped root asset, like the
    # default site. Establish it before taking the per-fixture exact baseline.
    case.ensure()
    lab.exec("python3", "-c", _CLEANUP_GUARDS, case.zone, case.name, case.private)
    lab.exec("apache2ctl", "configtest")
    lab.exec("apache2ctl", "graceful")
    before = json.loads(lab.exec("python3", "-c", _APACHE_MANIFEST))
    try:
        yield case
    finally:
        if case.held is not None:
            case.release()
        lab.remove_domain(case.name)
        lab.remove_domain(case.parent)
        lab.exec("python3", "-c", _CLEANUP_GUARDS, case.zone, case.name, case.private)
        lab.exec("python3", "-c", _REFRESH_BINDINGS)
        for suffix in ("", ".dom", ".info"):
            lab.exec("rm", "-f", "--", "/var/lib/praho-transfer/" + case.archive + suffix)
        after = json.loads(lab.exec("python3", "-c", _APACHE_MANIFEST))
        assert before == after, sorted(
            path for path in before.keys() | after.keys() if before.get(path) != after.get(path)
        )


def _create_fixture(case: NativeNeutralCase) -> None:
    lab = case.lab
    case.ensure()  # Zone guard precedes native creation, closing the otherwise exposed window.
    lab.create_domain(case.parent, case.owner)
    parent_home = lab.exec("virtualmin", "list-domains", "--domain", case.parent, "--home-only").strip()
    case.tenant_write(parent_home + "/public_html/probe.txt", "PARENT-UNAFFECTED")
    assert_accepted(
        lab.quiet(
            "create-domain",
            {"domain": case.name, "parent": case.parent, "dir": "", "web": "", "ssl": "", "desc": "PRAHO account name"},
            timeout_seconds=180,
        )
    )
    case.child_home = lab.exec("virtualmin", "list-domains", "--domain", case.name, "--home-only").strip()
    case.tenant_write(case.child_home + "/public_html/probe.txt", "TENANT-STATIC")


def test_neutral_account_name_cannot_serve_tenant_content_during_native_lifecycle(  # noqa: PLR0915  # One native lifecycle with exact fixture teardown.
    neutral_case: NativeNeutralCase,
) -> None:
    case = neutral_case
    lab = case.lab
    _create_fixture(case)
    executed = case.child_home + "/executed-marker"
    case.tenant_write(
        case.child_home + "/public_html/probe.php",
        f'<?php file_put_contents({json.dumps(executed)}, "executed"); echo "TENANT-PHP"; ?>',
    )
    case.ensure()
    original = case.metadata()
    case.certificate = case.copied_certificate()
    case.ensure(original["certificate_sha256"])
    for config, path in _TENANT_VARIANTS:
        case.tenant_write(case.child_home + "/public_html/.htaccess", config)
        for scheme in ("http", "https"):
            case.neutral(scheme=scheme, path=path)
    case.tenant_write(case.child_home + "/public_html/.htaccess", "")
    for host in (
        case.name.upper(),
        case.name + ".",
        case.name.upper() + ".:443",
        "webmail." + case.name,
        "admin." + case.name,
        "probe.sub." + case.name,
    ):
        for scheme in ("http", "https"):
            case.neutral(host=host, scheme=scheme, path="probe.txt")
    hostless = case.response(scheme="https", options={"hostless": True})
    assert hostless["rc"] == 0 and hostless["code"] == "400" and "TENANT" not in hostless["body"]
    case.neutral(host=case.parent, options={"absolute": "http://" + case.name + "/probe.php"})
    case.parent_response()

    case.native("disable-domain", case.name, cascade=True)
    case.tenant_write(case.child_home + "/public_html/disabled_by_virtualmin.html", "TENANT-STATIC")
    case.neutral(scheme="https")
    case.parent_response()
    case.native("disable-domain", case.parent, cascade=True)
    case.neutral(scheme="https")
    case.native("enable-domain", case.parent)
    case.neutral(scheme="https")
    case.parent_response()
    case.native("disable-domain", case.parent, cascade=True)
    case.native("enable-domain", case.parent, cascade=True)
    case.source_barrier_roundtrip()
    case.parent_response()
    case.tenant_write(
        case.child_home + "/public_html/.htaccess",
        '<If "true">\nErrorDocument 503 /probe.php\nHeader always set Set-Cookie "preview_probe=tenant; Path=/"\n</If>\n',
    )
    case.hold()
    case.parent_response(held=True)
    for scheme in ("http", "https"):
        case.neutral(scheme=scheme)
    assert (
        lab.exec(
            "python3", "-c", "from pathlib import Path;import sys;print(int(Path(sys.argv[1]).exists()))", executed
        ).strip()
        == "0"
    )
    assert case.held is not None
    run_held_target_node(case.held, "activate", enabled=True)
    case.native("enable-domain", case.parent, cascade=True)
    case.release()
    case.parent_response()
    case.neutral(scheme="https")
    renewed = case.rotate_to_full_chain()
    assert renewed != original["certificate_sha256"]
    case.ensure(renewed)
    case.certificate = case.private + "/root.pem"  # External trust only; the server must send its intermediate.
    case.neutral(scheme="https")
    assert (
        lab.exec(
            "python3",
            "-c",
            'import pathlib,sys;print(len(list((pathlib.Path(sys.argv[1]).parent/"versions").iterdir())))',
            case.manifest,
        ).strip()
        == "1"
    )
    # An orphan relationship cannot authorize removal while any native child exists.
    native_outcomes = []
    real_run = AnsibleService.run_playbook

    def observe_native(*args: Any, **kwargs: Any) -> Any:
        assert args[2] == "virtualmin_account_name_neutral.yml"
        outcome = real_run(*args, **kwargs)
        native_outcomes.append(outcome)
        return outcome

    with patch.object(AnsibleService, "run_playbook", observe_native):
        present_orphan = retire_account_name_neutral(lab.server, zone=case.zone, name=case.name, customer_user="")
    assert present_orphan.is_err()
    assert retriability_of(present_orphan) == Retriability.UNKNOWN
    assert len(native_outcomes) == 1 and native_outcomes[0].is_ok()
    assert not native_outcomes[0].unwrap().success
    assert "NEUTRAL_REFUSED=The native provider child still exists" in native_outcomes[0].unwrap().stdout
    case.neutral(scheme="https")
    lab.remove_domain(case.name)
    case.neutral(scheme="https")  # Native cert deletion cannot break the independent protected copy.
    retired = retire_account_name_neutral(lab.server, zone=case.zone, name=case.name, customer_user="")
    assert retired.is_ok(), retired.unwrap_err() if retired.is_err() else ""
    assert case.metadata()["phase"] == "retired"
    assert (
        lab.exec(
            "python3",
            "-c",
            'import pathlib,sys;print(len(list(pathlib.Path(sys.argv[1]).parent.rglob("*.pem"))))',
            case.manifest,
        ).strip()
        == "0"
    )
    case.neutral()
    case.parent_response()


def test_neutral_explicit_ip_binding_preserves_another_name_and_bridge_retirement(
    neutral_case: NativeNeutralCase,
) -> None:
    """Regression: loopback 404 once hid actual-IP tenant HTTP and verified HTTPS 200."""
    case, lab = neutral_case, neutral_case.lab
    second = NativeNeutralCase(lab)
    bridge_id = str(uuid4())
    try:
        _create_fixture(case)
        _create_fixture(second)
        second.ensure()
        second.certificate = second.copied_certificate()
        before = second.metadata()
        address = lab.exec("hostname", "-I").split()[0]
        lab.exec(
            "python3",
            "-c",
            "import pathlib,sys;names=set(sys.argv[1:3]);address=sys.argv[3];"
            "[(p.write_text(p.read_text().replace('*:80',address+':80').replace('*:443',address+':443'))) "
            "for p in pathlib.Path('/etc/apache2/sites-enabled').glob('*.conf') "
            "if any('ServerName '+name+'\\n' in p.read_text() for name in names)]",
            case.name,
            case.parent,
            address,
        )
        case.ensure()
        case.certificate = case.copied_certificate()
        assert case.metadata()["native_bindings"] == {"80": [address], "443": [address]}
        for scheme in ("http", "https"):
            case.neutral(scheme=scheme, path="probe.txt", options={"address": address})
            second.neutral(scheme=scheme, path="probe.txt", options={"address": address})
        assert second.metadata()["named_config_sha256"] == before["named_config_sha256"]
        second.native("disable-domain", second.name)
        lab.exec(
            "python3",
            "/var/lib/praho/account-name-neutral/helper.py",
            "verify",
            "--name",
            second.name,
            "--owner",
            second.owner,
            "--parent",
            second.parent,
            "--parent-id",
            before["native_parent_id"],
            "--host",
            second.name,
        )
        # Use the production source bridge; its customer upstream is deliberately
        # unrequested here. The two-node bridge contract proves forwarding.
        bridge = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-bridge.py"
        docker = shutil.which("docker")
        assert docker is not None
        lab.exec("install", "-d", "-m", "0700", case.private)
        subprocess.run(  # noqa: S603  # Shipped helper and unique private directory in the fixed lab container.
            [docker, "cp", str(bridge), f"{lab.node.container}:{case.private}/bridge.py"],
            check=True,
            capture_output=True,
            timeout=60,
        )
        lab.exec("chown", "root:root", case.private + "/bridge.py")
        lab.exec("chmod", "0700", case.private + "/bridge.py")
        script = (
            "import importlib.util,sys;spec=importlib.util.spec_from_file_location('bridge',sys.argv[1]);"
            "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);node=m.NodeBridge();"
        )
        lab.exec(
            "python3",
            "-c",
            script + "manifest=node.prepare(sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],sys.argv[5]);"
            "node.install_source(sys.argv[2],next(i['public_certificate'] for i in manifest['vhosts'] if i.get('public_certificate')))",
            case.private + "/bridge.py",
            bridge_id,
            case.parent,
            case.name,
            address,
        )
        case.neutral(scheme="https", options={"address": address})
        lab.remove_domain(case.name)
        lab.remove_domain(case.parent)
        case.neutral(scheme="https", options={"address": address})
        lab.exec("python3", "-c", script + "node.remove_source(sys.argv[2])", case.private + "/bridge.py", bridge_id)
        case.neutral(scheme="https", options={"address": address})  # Independent named copy keeps TLS until retirement.
        retired = retire_account_name_neutral(lab.server, zone=case.zone, name=case.name, customer_user=case.owner)
        assert retired.is_ok(), retired.unwrap_err() if retired.is_err() else ""
        case.neutral(options={"address": address})
        second.neutral(scheme="https", options={"address": address})
        lab.exec(
            "python3",
            "/var/lib/praho/account-name-neutral/helper.py",
            "verify",
            "--name",
            second.name,
            "--owner",
            second.owner,
            "--parent",
            second.parent,
            "--parent-id",
            before["native_parent_id"],
            "--host",
            second.name,
        )
    finally:
        # Remove only this UUID's transport/state and these unique fixture names.
        lab.exec(
            "python3",
            "-c",
            "import pathlib,shutil,sys;p=pathlib.Path('/etc/apache2/conf-enabled')/('praho-migration-'+sys.argv[1]+'.conf');p.unlink(missing_ok=True);shutil.rmtree(pathlib.Path('/var/lib/praho/bridges')/sys.argv[1],ignore_errors=True)",
            bridge_id,
        )
        lab.exec(
            "python3",
            "-c",
            "import pathlib,sys;p=pathlib.Path('/etc/hosts');tag='praho-bridge:'+sys.argv[1];text=''.join(line for line in p.read_text().splitlines(keepends=True) if line.partition('#')[2].strip()!=tag);p.write_text(text)",
            bridge_id,
        )
        lab.remove_domain(second.name)
        lab.remove_domain(second.parent)
        lab.exec("python3", "-c", _CLEANUP_GUARDS, second.zone, second.name, second.private)
        lab.exec("python3", "-c", _REFRESH_BINDINGS)


def test_neutral_expired_native_and_copied_leaf_can_be_repaired_without_exposing_content(
    neutral_case: NativeNeutralCase,
) -> None:
    case, lab = neutral_case, neutral_case.lab
    _create_fixture(case)
    fingerprint = case.rotate_to_full_chain()
    case.ensure(fingerprint)
    case.certificate = case.private + "/root.pem"
    case.neutral(scheme="https", path="probe.txt")
    # Construct the exact private historical snapshot that remains when both
    # native and copied certificates expire. No clock or system trust changes.
    lab.exec(
        "python3",
        "-c",
        "import pathlib,sys;p=pathlib.Path(sys.argv[1]);(p/'index').write_text('');(p/'serial').write_text('10\\n');(p/'issued').mkdir();"
        "(p/'ca.conf').write_text('[ca]\\ndefault_ca=owned\\n[owned]\\ndatabase='+str(p/'index')+'\\nserial='+str(p/'serial')+'\\nnew_certs_dir='+str(p/'issued')+'\\ncertificate='+str(p/'intermediate.pem')+'\\nprivate_key='+str(p/'intermediate.key')+'\\ndefault_md=sha256\\npolicy=identity\\n[identity]\\ncommonName=supplied\\n[server]\\n'+(p/'leaf.ext').read_text())",
        case.private,
    )
    lab.exec(
        "openssl",
        "ca",
        "-batch",
        "-notext",
        "-config",
        case.private + "/ca.conf",
        "-extensions",
        "server",
        "-startdate",
        "20200101000000Z",
        "-enddate",
        "20210101000000Z",
        "-in",
        case.private + "/leaf.csr",
        "-out",
        case.private + "/expired.pem",
    )
    native = json.loads(lab.exec("python3", "-c", _NATIVE_TLS_PATHS, case.name))
    lab.exec(
        "python3",
        "-c",
        r"""
import hashlib,importlib.util,json,pathlib,sys
spec=importlib.util.spec_from_file_location('guard','/var/lib/praho/account-name-neutral/helper.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);guard=m.NeutralGuard()
p=pathlib.Path(sys.argv[1]);zone,name,owner=sys.argv[2:5]
bundle=b''.join((p/(n+'.pem')).read_bytes() for n in ('expired','intermediate','root'))
pathlib.Path(sys.argv[5]).write_bytes(bundle)
with guard.locked():
    directory=guard.name_directory(name);version=directory/'versions'/hashlib.sha256(bundle).hexdigest();guard.directory(version)
    guard.write(version/'chain.pem',bundle);guard.write(version/'key.pem',(p/'leaf.key').read_bytes())
    named=guard.config_path('name',name);guard.managed_config(named,guard.render('name',zone,name,version/'chain.pem',version/'key.pem'))
    value=guard.named_state('ready',zone,name,owner,guard.native(name,owner),guard.config_path('zone',zone),named)
    value['certificate_sha256']=m.leaf_fingerprint(bundle);guard.json_write(directory/'state.json',value);guard.reload()
""",
        case.private,
        case.zone,
        case.name,
        case.owner,
        native["certificate"],
    )
    expired = case.response(scheme="https", path="probe.txt")
    assert expired["rc"] != 0 and expired["code"] == "000"
    strict = ensure_account_name_neutral(lab.server, zone=case.zone, name=case.name, customer_user=case.owner)
    assert strict.is_err()
    prepared = prepare_account_name_neutral(lab.server, zone=case.zone, name=case.name, customer_user=case.owner)
    assert prepared.is_ok(), prepared.unwrap_err() if prepared.is_err() else ""
    assert case.metadata()["phase"] == "bootstrap"
    case.neutral(path="probe.txt")
    still_strict = ensure_account_name_neutral(lab.server, zone=case.zone, name=case.name, customer_user=case.owner)
    assert still_strict.is_err()
    # Reinstall the already generated valid native pair, then demand its exact
    # public leaf before considering certificate readiness restored.
    lab.exec(
        "python3",
        "-c",
        "import pathlib,sys;p=pathlib.Path(sys.argv[1]);pathlib.Path(sys.argv[2]).write_bytes(b''.join((p/(n+'.pem')).read_bytes() for n in ('leaf','intermediate','root')))",
        case.private,
        native["certificate"],
    )
    lab.exec("apache2ctl", "configtest")
    lab.exec("apache2ctl", "graceful")
    case.ensure(fingerprint)
    assert case.metadata()["phase"] == "ready"
    case.neutral(scheme="https", path="probe.txt")
