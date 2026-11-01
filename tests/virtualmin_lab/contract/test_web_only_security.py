"""Native session checks: API authentication must not grant remote root UI access."""

from __future__ import annotations

import re
import subprocess
import time
from urllib.parse import urlsplit

from apps.common.outbound_http import OutboundPolicy, safe_request
from apps.infrastructure.ansible_service import AnsibleService, node_admin_allowed_cidrs
from apps.provisioning.virtualmin_gateway import explicit_rejection
from tests.virtualmin_lab.contract.harness import Lab


def harden_webmin(lab: Lab) -> None:
    assert lab.server.api_username != "root", "lab enrollment must persist the dedicated API identity"
    result = AnsibleService().run_playbook(
        lab.server.node_deployment,
        "virtualmin_harden.yml",
        {"security_hardening_approved": True, "praho_api_user": lab.server.api_username},
        timeout_seconds=1200,
    )
    assert result.is_ok(), "hardening transport failed"
    assert result.unwrap().success, "native hardening did not complete"
    healthy = lab.gateway.test_connection()
    assert healthy.is_ok() and healthy.unwrap()["healthy"] is True


def test_discovery_socket_is_closed_even_when_its_saved_configuration_is_disabled(lab: Lab) -> None:
    harden_webmin(lab)
    # Reproduce an interrupted old conversion: config says disabled but the
    # already-running daemon still owns the old UDP socket.
    program = r"""our($no_acl_check,%gconfig); $no_acl_check=1;
$ENV{'WEBMIN_CONFIG'}='/etc/webmin'; $ENV{'WEBMIN_VAR'}='/var/webmin';
chdir('/usr/share/webmin') or die; $0='/usr/share/webmin/praho-native-test';
require './web-lib.pl'; &init_config(); my %conf; &get_miniserv_config(\%conf);
$conf{'listen'}=shift(@ARGV); &put_miniserv_config(\%conf);
"""
    try:
        lab.exec("perl", "-e", program, "10000")
        lab.exec("systemctl", "restart", "webmin.service")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if lab.exec("ss", "-H", "-uln", "sport = :10000").strip():
                break
            time.sleep(0.2)
        assert lab.exec("ss", "-H", "-uln", "sport = :10000").strip(), "positive control: no discovery socket"
        lab.exec("perl", "-e", program, "")
        harden_webmin(lab)
        assert not lab.exec("ss", "-H", "-uln", "sport = :10000").strip()
        pid = lab.exec("systemctl", "show", "webmin.service", "-p", "MainPID", "--value")
        harden_webmin(lab)
        assert lab.exec("systemctl", "show", "webmin.service", "-p", "MainPID", "--value") == pid
    finally:
        lab.exec("perl", "-e", program, "")
        lab.exec("systemctl", "restart", "webmin.service")


def mint_path(lab: Lab) -> str:
    # Deliberately bypass PRAHO's allowlist in this attack test. Native master API
    # supports this command even though PRAHO never exposes it.
    minted = lab.gateway._execute_http_request({"program": "create-login-link", "root": "", "json": "1"})
    payload = minted.json()
    assert payload.get("status") == "success", "positive control: root link could not be minted"
    match = re.search(r"https?://[^\s]+/session_login\.cgi\?session=[^\s]+", payload["output"])
    assert match is not None, "native root command returned no session URL"
    target = urlsplit(match.group(0))
    return target.path + "?" + target.query


def webmin_policy(lab: Lab) -> OutboundPolicy:
    return OutboundPolicy(
        name="virtualmin",
        verify_tls=False,
        tls_cert_fingerprint=lab.server.ssl_cert_fingerprint,
        blocked_ports=frozenset(),
        retry_connection_errors=False,
    )


def test_web_only_principals_and_login_links(lab: Lab) -> None:
    """Exercise real miniserv ACL enforcement, including a spoofed forwarding header."""
    harden_webmin(lab)
    policy = webmin_policy(lab)
    for headers in ({}, {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}):
        url = f"https://{lab.server.hostname}:{lab.server.api_port}{mint_path(lab)}"
        response = safe_request("GET", url, policy=policy, headers=headers, allow_redirects=False)
        if response.status_code == 302:
            response = safe_request(
                "GET",
                f"https://{lab.server.hostname}:{lab.server.api_port}/sysinfo.cgi",
                policy=policy,
                headers=headers,
                cookies=response.cookies,
                allow_redirects=False,
            )
        assert response.status_code == 403, "remote root session escaped the per-user source restriction"

    # The same minted capability must still work locally, through the restricted
    # operator tunnel's destination. Pass its secret through stdin, never argv/logs.
    path = mint_path(lab)
    local = subprocess.run(  # noqa: S603 -- Fixed local lab invocation; secret URL travels only on stdin.
        ["docker", "exec", "-i", lab.node.container, "curl", "--config", "-"],  # noqa: S607 -- Developer Docker CLI.
        input=f'url = "https://127.0.0.1:10000{path}"\ninsecure\nsilent\noutput = "/dev/null"\nwrite-out = "%{{http_code}}"\n',
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    assert local.stdout in {"200", "302"}, "loopback operator access must remain usable"

    customer = lab.gateway._execute_http_request(
        {"program": "create-login-link", "domain": "contract.praho.test", "json": "1"}
    )
    assert customer.json().get("status") == "failure"
    assert "no Webmin login" in (explicit_rejection(customer.text) or ""), "customer Webmin removal was not effective"


def test_existing_root_session_is_invalidated_by_conversion(lab: Lab) -> None:
    harden_webmin(lab)
    policy = webmin_policy(lab)
    origin = f"https://{lab.server.hostname}:{lab.server.api_port}"
    # Open only this disposable lab principal long enough to establish the old
    # session. Always restore native policy, including when the positive control fails.
    program = r"""use strict; use warnings;
our($no_acl_check,%gconfig); $no_acl_check=1;
$ENV{'WEBMIN_CONFIG'}='/etc/webmin'; $ENV{'WEBMIN_VAR'}='/var/webmin';
chdir('/usr/share/webmin') or die; $0='/usr/share/webmin/praho-native-test';
require './web-lib.pl'; &init_config(); &foreign_require('acl','acl-lib.pl');
my $root=&acl::get_user('root'); $root->{'allow'}='';
&acl::modify_user('root',$root); &reload_miniserv();
"""
    try:
        lab.exec("perl", "-e", program)
        login = safe_request("GET", origin + mint_path(lab), policy=policy, allow_redirects=False)
        assert login.status_code == 302 and login.cookies, "positive control: no usable root session"
        before = safe_request(
            "GET", origin + "/sysinfo.cgi", policy=policy, cookies=login.cookies, allow_redirects=False
        )
        assert before.status_code == 200 and "session_login.cgi" not in before.headers.get("Location", ""), (
            "positive control: root session did not authenticate"
        )
        assert not re.search(r'name=["\x27]pass["\x27]', before.text), "positive control showed a login form"
    finally:
        lab.exec("perl", "/usr/local/sbin/praho-webmin-web-only", lab.server.api_username, *node_admin_allowed_cidrs())
    after = safe_request("GET", origin + "/sysinfo.cgi", policy=policy, cookies=login.cookies, allow_redirects=False)
    assert after.status_code in {401, 403} or (
        "session_login.cgi" in after.text and re.search(r'name=["\x27]pass["\x27]', after.text)
    ), "an old root session still has authenticated UI access"
