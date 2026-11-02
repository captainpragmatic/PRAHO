"""Native DNS publication must not synchronize an unapproved copied alias zone."""

import ipaddress
import json
import subprocess
from pathlib import Path
from uuid import uuid4

from tests.virtualmin_lab.components.conftest import MixedSource

ZONE_INVENTORY = r"""package virtual_server;
use JSON::PP;$main::no_acl_check++;
$ENV{'WEBMIN_CONFIG'}='/etc/webmin';$ENV{'WEBMIN_VAR'}='/var/webmin';
$0='/usr/share/webmin/virtual-server/modify-dns.pl';chdir('/usr/share/webmin/virtual-server') or die;
require './virtual-server-lib.pl';my $d=&get_domain_by('dom',$ARGV[0]);die unless $d;
my ($records,$file)=&get_domain_dns_records_and_file($d,1);
die unless ref($records) eq 'ARRAY' && defined($file);
print JSON::PP->new->canonical(1)->encode({'records'=>$records,'zone'=>&read_file_contents($file)});
"""


def zone_inventory(mixed_source: MixedSource, domain: str) -> str:
    return mixed_source.lab.exec("perl", "-e", ZONE_INVENTORY, domain)


def test_native_routing_leaves_copied_dns_alias_zones_and_primary_unchanged(mixed_source: MixedSource) -> None:
    lab = mixed_source.lab
    alias = "compalias" + uuid4().hex[:10] + ".praho.test"
    directory = lab.exec("mktemp", "-d", "/var/lib/praho-routing-alias.XXXXXXXX").strip()
    helpers = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks/files"
    try:
        lab.exec("virtualmin", "create-domain", "--domain", alias, "--alias", mixed_source.domain, "--dns")
        alias_id = lab.exec("virtualmin", "list-domains", "--domain", alias, "--id-only").strip()
        flags = lab.exec("grep", "-E", "^(alias|aliasdns|dns)=", "/etc/webmin/virtual-server/domains/" + alias_id)
        assert "alias=" + mixed_source.domain_id in flags and "dns=1" in flags and "aliasdns=1" not in flags
        original_primary = zone_inventory(mixed_source, mixed_source.domain)
        original_alias = zone_inventory(mixed_source, alias)
        source_ipv4 = str(
            ipaddress.IPv4Address(lab.exec("dig", "+short", "@127.0.0.1", mixed_source.domain, "A").strip())
        )
        source_ipv6 = lab.exec("dig", "+short", "@127.0.0.1", mixed_source.domain, "AAAA").strip()
        if source_ipv6:
            source_ipv6 = str(ipaddress.IPv6Address(source_ipv6))
        for filename in ("praho-component-routing.py", "praho-component-routing.pl"):
            result = subprocess.run(  # noqa: S603 -- public helper code, exact owned disposable container
                ["docker", "exec", "-i", lab.node.container, "tee", directory + "/" + filename],  # noqa: S607
                input=(helpers / filename).read_text(),
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert result.returncode == 0
        result = subprocess.run(  # noqa: S603 -- native locked DNS helper, fixed owned source identity on stdin
            ["docker", "exec", "-i", lab.node.container, "perl", directory + "/praho-component-routing.pl"],  # noqa: S607
            input=json.dumps(
                {
                    "request": {
                        "domain_id": mixed_source.domain_id,
                        "domain": mixed_source.domain,
                        "owner": mixed_source.owner,
                    },
                    "network": {
                        "source_ipv4": source_ipv4,
                        "target_ipv4": "192.0.2.20",
                        "source_ipv6": source_ipv6,
                        "target_ipv6": "2001:db8::20" if source_ipv6 else "",
                    },
                }
            ),
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"mode": "operator_dns_required"}
        assert zone_inventory(mixed_source, mixed_source.domain) == original_primary
        assert zone_inventory(mixed_source, alias) == original_alias
    finally:
        lab.remove_domain(alias)
        lab.exec("rm", "-rf", "--", directory)
