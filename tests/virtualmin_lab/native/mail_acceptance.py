#!/usr/bin/env python3
"""Actual Virtualmin emitter attempts plus retained SMTP/IMAP/contact traffic.

Runs only inside mail_fixture's newly owned full-mail container (or the same
explicitly owned provider source fixture). No arbitrary fleet target is accepted.
"""

from __future__ import annotations

import hashlib
import imaplib
import json
import os
import pwd
import socketserver
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
from pathlib import Path
from uuid import UUID, uuid4

sys.path.insert(0, "/usr/local/lib/praho")
sys.path.insert(0, "/root/praho-native-mail")

from retained_probe import (
    assert_retained_services,
    unix_identity,
)

VMIN = "/usr/sbin/virtualmin"
OPERATORS = {
    name: name + "-operator@native-mail.example.invalid"
    for name in ("quota", "bandwidth", "backup", "acme", "application", "status")
}
CUSTOMER = "customer@native-mail.example.invalid"
PASSWORD = "Disposable-native-mail-fixture-only-776"
ROOT = Path("/root/praho-native-mail")
PERL_PREFIX = """package virtual_server; use JSON::PP; $main::no_acl_check=1;
$ENV{'WEBMIN_CONFIG'}='/etc/webmin';$ENV{'WEBMIN_VAR'}='/var/webmin';
$0='/usr/share/webmin/virtual-server/praho-mail-fixture.pl';
chdir('/usr/share/webmin/virtual-server') or die 'Missing native fixture';
require './virtual-server-lib.pl';my $p=JSON::PP->new->decode(do{local $/;<STDIN>});
require './feature-status.pl' if !defined(&setup_status);
"""


def run(argv: list[str], *, payload: str | None = None, timeout: int = 120) -> str:
    directory = (
        Path(argv[1]).parent
        if len(argv) > 1 and argv[0] == "/usr/bin/perl" and argv[1].startswith("/usr/share/webmin/")
        else None
    )
    result = subprocess.run(  # noqa: S603 -- Fixed native executables, canonical owned fixture argv; no shell.
        argv,
        input=payload,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        cwd=directory,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "HOME": "/root",
            "WEBMIN_CONFIG": "/etc/webmin",
            "WEBMIN_VAR": "/var/webmin",
        },
    )
    if result.returncode:
        raise AssertionError("Native mail fixture command failed: " + result.stderr[-2500:] + result.stdout[-1000:])
    return result.stdout.strip()


def perl(program: str, payload: dict[str, object] | None = None) -> dict[str, object]:
    text = run(["/usr/bin/perl", "-e", PERL_PREFIX + program], payload=json.dumps(payload or {}))
    marker = "PRAHO_NATIVE_MAIL="
    if marker not in text:
        raise AssertionError("Native fixture did not return its bounded semantic result")
    return json.loads(text.rsplit(marker, 1)[1])


class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.wfile.write(b"220 native-fixture ESMTP\r\n")
        data = False
        while True:
            line = self.rfile.readline(65537)
            if not line or len(line) > 65536:
                return
            text = line.decode("utf-8", errors="replace").strip()
            if data:
                if text == ".":
                    data = False
                    self.wfile.write(b"250 accepted\r\n")
                continue
            verb = text.upper()
            if verb.startswith("RCPT TO:"):
                recipient = text.split(":", 1)[1].strip().strip("<>").lower()
                self.server.attempts.append(recipient)
                self.wfile.write(b"250 recipient accepted\r\n")
            elif verb == "DATA":
                data = True
                self.wfile.write(b"354 End with dot\r\n")
            elif verb == "QUIT":
                self.wfile.write(b"221 closing\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


class MailSink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), SMTPHandler)
        self.attempts: list[str] = []


def configure_sink(port: int) -> None:
    perl(
        r"""my %mail;&read_file('/etc/webmin/mailboxes/config',\%mail);
$mail{'send_mode'}='127.0.0.1';$mail{'smtp_port'}=$p->{'port'};$mail{'smtp_ssl'}=0;
delete $mail{'smtp_user'};delete $mail{'smtp_pass'};&write_file('/etc/webmin/mailboxes/config',\%mail);
my %global;&read_file('/etc/webmin/config',\%global);$global{'webmin_email_to'}=$p->{'operator'};
&write_file('/etc/webmin/config',\%global);my %status;&read_file('/etc/webmin/status/config',\%status);
$status{'sched_email'}=$p->{'status_operator'};&write_file('/etc/webmin/status/config',\%status);
print 'PRAHO_NATIVE_MAIL={}';""",
        {"port": port, "operator": OPERATORS["acme"], "status_operator": OPERATORS["status"]},
    )


def create_domain(
    domain: str, owner: str, *, template: str | None = None, notify: bool = False, web_only: bool = False
) -> None:
    argv = [
        VMIN,
        "create-domain",
        "--domain",
        domain,
        "--user",
        owner,
        "--pass",
        PASSWORD,
        "--email",
        CUSTOMER,
        "--unix",
        "--dir",
        "--web",
        "--ssl",
        "--mysql",
        "--logrotate",
        "--quota",
        "0",
        "--uquota",
        "0",
        "--bandwidth",
        "0",
    ]
    if not web_only:
        argv += ["--mail", "--dns"]
    if template is not None:
        argv += ["--template", template]
    if not notify:
        argv += ["--no-email"]
    run(argv, timeout=180)


def archive_before_handover(stem: str) -> dict[str, object]:
    """A separate disposable web-only account; retained mailbox accounts are never deleted."""
    domain, owner = stem + "archive.praho.test", stem + "archive"
    create_domain(domain, owner, web_only=True)
    metadata = perl(
        """my $d=&get_domain_by('dom',$p->{'domain'});die 'Missing archive fixture' if !$d || $d->{'mail'};
&lock_domain($d);$d=&get_domain($d->{'id'},undef,1);$d->{'letsencrypt_email'}=0;$d->{'letsencrypt_email_master'}=1;
$d->{'letsencrypt_renew'}=1;&save_domain($d);&unlock_domain($d);
print 'PRAHO_NATIVE_MAIL=',JSON::PP->new->encode({domain=>$d->{'dom'},owner=>$d->{'user'},home=>$d->{'home'},
domain_id=>$d->{'id'},ssl_cert=>$d->{'ssl_cert'},ssl_key=>$d->{'ssl_key'}});""",
        {"domain": domain},
    )
    marker = Path(str(metadata["home"])) / "public_html/pre-handover-archive.txt"
    marker.write_text("Native archive ownership fixture " + domain)
    user = pwd.getpwnam(owner)
    os.chown(marker, user.pw_uid, user.pw_gid)
    archive = ROOT / "pre-handover-native.tar.gz"
    assert not archive.exists()
    run([VMIN, "backup-domain", "--domain", domain, "--dest", str(archive), "--all-features"], timeout=180)
    archive.chmod(0o600)
    with tarfile.open(archive, "r:gz") as bundle:
        members = [member for member in bundle if Path(member.name).name == domain + "_virtualmin"]
        assert len(members) == 1 and members[0].isfile() and members[0].size <= 1024 * 1024
        stream = bundle.extractfile(members[0])
        assert stream is not None
        fields = dict(line.split("=", 1) for line in stream.read().decode().splitlines() if "=" in line)
        assert fields["dom"] == domain and fields["user"] == owner and fields["letsencrypt_email"] == "0"
        assert fields.get("mail") != "1"
    return {
        **metadata,
        "archive": str(archive),
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "marker_sha256": hashlib.sha256(marker.read_bytes()).hexdigest(),
    }


def restore_after_handover(metadata: dict[str, object], sink: MailSink) -> dict[str, object]:
    """Actual missing-domain recreation restores whole metadata, unlike an existing-domain merge."""
    domain, owner = str(metadata["domain"]), str(metadata["owner"])
    archive = Path(str(metadata["archive"]))
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == metadata["archive_sha256"]
    run([VMIN, "delete-domain", "--domain", domain])
    assert not Path(str(metadata["home"])).exists()
    argv = [VMIN, "restore-domain", "--domain", domain, "--source", str(archive), "--only-features"]
    for feature in ("virtualmin", "unix", "dir", "web", "ssl", "mysql", "logrotate"):
        argv += ["--feature", feature]
    run(argv, timeout=180)
    restored = perl(
        """my $d=&get_domain_by('dom',$p->{'domain'});die 'Archive owner/settings not restored' if !$d
|| $d->{'user'} ne $p->{'owner'} || $d->{'mail'} || $d->{'letsencrypt_email'} ne '0';
print 'PRAHO_NATIVE_MAIL=',JSON::PP->new->encode({domain_id=>$d->{'id'},ssl_cert=>$d->{'ssl_cert'},ssl_key=>$d->{'ssl_key'}});""",
        {"domain": domain, "owner": owner},
    )
    marker = Path(str(metadata["home"])) / "public_html/pre-handover-archive.txt"
    assert hashlib.sha256(marker.read_bytes()).hexdigest() == metadata["marker_sha256"]
    prepare_due_certificate(domain, restored)
    perl(
        """my $d=&get_domain_by('dom',$p->{'domain'});&lock_domain($d);$d=&get_domain($d->{'id'},undef,1);
die 'Actual archive owner flag was repaired before the emitter proof' if $d->{'letsencrypt_email'} ne '0';
$d->{'letsencrypt_last'}=0;delete $d->{'letsencrypt_first_failure'};&save_domain($d);&unlock_domain($d);
&save_module_config_keys({last_letsencrypt_mass_renewal=>0});&apply_letsencrypt_cert_renewals();
# Isolate the subsequent primary-domain renewal controls; this is fixture-only.
&lock_domain($d);$d=&get_domain($d->{'id'},undef,1);$d->{'letsencrypt_renew'}=0;&save_domain($d);&unlock_domain($d);
print 'PRAHO_NATIVE_MAIL={}';""",
        {"domain": domain},
    )
    assert CUSTOMER not in sink.attempts, "Actual pre-handover archive reopened native customer mail"
    assert OPERATORS["acme"] in sink.attempts, "Native restored-domain master alert was lost"
    return {
        "archive_sha256": metadata["archive_sha256"],
        "restored_domain_id": restored["domain_id"],
        "native_cli_restore": True,
        "public_platform_restore": False,
    }


def prepare_permissive_source(domain: str) -> dict[str, object]:
    metadata = perl(
        r"""my $d=&get_domain_by('dom',$p->{'domain'});die 'Missing fixture' if !$d;
my $t={%{&get_template(0)}};delete $t->{'id'};delete $t->{'standard'};delete $t->{'default'};
$t->{'name'}='PRAHO native mail fixture';$t->{'mail_on'}='yes';$t->{'mail'}='Native signup fixture';
$t->{'newuser_on'}='yes';$t->{'newuser'}='Native user fixture';$t->{'updateuser_on'}='yes';
$t->{'updateuser'}='Native updated user fixture';$t->{'mail_cc'}=$p->{'customer'};$t->{'mail_bcc'}=$p->{'customer'};
$t->{'newuser_cc'}=$p->{'customer'};$t->{'updateuser_bcc'}=$p->{'customer'};
$t->{'newuser_to_owner'}=1;$t->{'newuser_to_reseller'}=1;$t->{'updateuser_to_owner'}=1;
$t->{'status'}=$p->{'customer'}.','.$p->{'status_operator'};$t->{'statusonly'}=0;$t->{'statussslcert'}=1;$t->{'ssl_email'}=0;
&save_template($t);&lock_domain($d);$d=&get_domain($d->{'id'},undef,1);$d->{'template'}=$t->{'id'};
$d->{'letsencrypt_email'}=0;$d->{'letsencrypt_email_master'}=1;&save_domain($d);&unlock_domain($d);
&save_module_config_keys({quota_users=>1,quota_mailbox_send=>1,quota_email=>$p->{'quota_operator'},
bw_owner=>1,bw_email=>$p->{'bandwidth_operator'},bw_disable=>1,bw_enable=>1,scriptwarn_enabled=>1,
scriptwarn_email=>'owner reseller '.$p->{'application_operator'},scriptwarn_notify=>0});
&setup_scriptwarn_job(1,'hourly');&set_all_null_print();&setup_status($d);
for my $m (&status::list_services()) {next if $m->{'virtualmin'} ne $d->{'id'};
$m->{'nosched'}=0;$m->{'fails'}=1;
if($m->{'type'} eq 'http'){$m->{'host'}='127.0.0.1';$m->{'port'}=80;$m->{'ssl'}=0;}
if($m->{'type'} eq 'sslcert'){$m->{'url'}='https://127.0.0.1:443/';}
&status::save_service($m);}
my $b={dest=>'/root/praho-native-mail/scheduled-backup.tar.gz',fmt=>0,doms=>$d->{'id'},
features=>'dir',email=>$p->{'backup_operator'},email_doms=>1,email_err=>0,enabled=>0};
&save_scheduled_backup($b);
my @extra;for my $kind ('customer','mixed') {
my $email=$p->{'customer'}.($kind eq 'mixed' ? ','.$p->{'backup_operator'} : '');
my $other={%$b,dest=>'/root/praho-native-mail/scheduled-backup-'.$kind.'.tar.gz',email=>$email,email_doms=>0};
delete $other->{'id'};&save_scheduled_backup($other);push @extra,$other->{'id'};}
print 'PRAHO_NATIVE_MAIL=',JSON::PP->new->canonical->encode({domain_id=>$d->{'id'},template=>$t->{'id'},
backup=>$b->{'id'},backup_extra=>\@extra,home=>$d->{'home'},ssl_cert=>$d->{'ssl_cert'},ssl_key=>$d->{'ssl_key'}});""",
        {"domain": domain, "customer": CUSTOMER, **{name + "_operator": value for name, value in OPERATORS.items()}},
    )
    run(["/usr/bin/perl", "/usr/share/webmin/status/monitor.pl", "--force"])
    perl(
        r"""my $d=&get_domain_by('dom',$p->{'domain'});&foreign_require('status');
my %old;&read_file($status::oldstatus_file,\%old);my $checked=0;
for my $m (&status::list_services()) {next if $m->{'virtualmin'} ne $d->{'id'} || $m->{'type'} ne 'http';
die 'Native HTTP monitor initial-up baseline missing' if $old{$m->{'id'}} !~ /(?:^| )\*=1(?: |$)/;$checked++;}
die 'Native HTTP fixture monitor missing' if !$checked;print 'PRAHO_NATIVE_MAIL={}';""",
        {"domain": domain},
    )
    return metadata


def mailbox_contents(owner: str) -> set[str]:
    client = imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=ssl._create_unverified_context())  # noqa: S323 -- Exact local disposable native certificate.
    try:
        client.login(owner, PASSWORD)
        assert client.select("INBOX")[0] == "OK"
        status, ids = client.search(None, "ALL")
        assert status == "OK"
        result = set()
        for identifier in ids[0].split():
            status, records = client.fetch(identifier, "(RFC822)")
            assert status == "OK"
            result.update(hashlib.sha256(record[1]).hexdigest() for record in records if isinstance(record, tuple))
        return result
    finally:
        client.logout()


def resource_policy_snapshot() -> dict[str, object]:
    return perl(
        """my %warnings=map {$_=>$config{$_}//''} qw(quota_users quota_mailbox_send bw_owner
scriptwarn_enabled scriptwarn_email);my @domains=sort {$a->{'id'} cmp $b->{'id'}} &list_domains();
print 'PRAHO_NATIVE_MAIL=',JSON::PP->new->canonical->encode({warnings=>\\%warnings,
actions=>[$config{'bw_disable'}//'', $config{'bw_enable'}//''],
domains=>[map {{id=>$_->{'id'},disabled=>$_->{'disabled'}//'',protected=>$_->{'bw_no_disable'}//''}} @domains]});"""
    )


def verify_resource_only_policy(domain: str, sink: MailSink) -> None:
    before = resource_policy_snapshot()
    assert before["actions"] == ["1", "1"], "Native destructive bandwidth fixture was not established"
    # Userspace fixture exercises the same resource mechanism; public adoption
    # additionally requires the unavailable Ubuntu/kernel qualification gate.
    run(
        ["/usr/bin/perl", "/usr/local/lib/praho/praho-notification-policy.pl", "resource"],
    )
    after = resource_policy_snapshot()
    assert after["actions"] == ["0", "0"]
    assert after["warnings"] == before["warnings"], "Kernel adoption changed native warning ownership"
    assert [(row["id"], row["disabled"]) for row in after["domains"]] == [
        (row["id"], row["disabled"]) for row in before["domains"]
    ], "Resource adoption changed a domain's enabled state"
    assert all(row["protected"] == "1" for row in after["domains"])
    assert not Path("/var/lib/praho/hosting/notification-owner").exists()
    sink.attempts.clear()
    perl(
        """my $d=&get_domain_by('dom',$p->{'domain'});&lock_domain($d);$d=&get_domain($d->{'id'},undef,1);
$d->{'bw_limit'}=1;$d->{'bw_notify'}=0;&save_domain($d);&unlock_domain($d);
my $bw=&get_bandwidth($d);$bw->{'web_'.int(time()/86400)}=1000000;&save_bandwidth($d,$bw);
print 'PRAHO_NATIVE_MAIL={}';""",
        {"domain": domain},
    )
    run(["/usr/bin/perl", "/usr/share/webmin/virtual-server/bw.pl", domain])
    assert CUSTOMER in sink.attempts, "Resource-only adoption lost the actual native bandwidth warning"
    assert all(not row["disabled"] for row in resource_policy_snapshot()["domains"])


def contact_form(owner: str, domain: str, home: Path) -> None:
    path = home / "public_html/native-contact.php"
    subject = "native-contact-" + uuid4().hex
    path.write_text(
        "<?php echo mail('"
        + owner
        + "@"
        + domain
        + "','"
        + subject
        + "','Retained contact form fixture')?'queued':'failed';"
    )
    account = pwd.getpwnam(owner)
    os.chown(path, account.pw_uid, account.pw_gid)
    request = urllib.request.Request("http://127.0.0.1/native-contact.php", headers={"Host": domain})
    assert urllib.request.urlopen(request, timeout=20).read() == b"queued"  # noqa: S310 -- Fixed loopback fixture URL, canonical owned Host.
    deadline = time.monotonic() + 20
    while True:
        client = imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=ssl._create_unverified_context())  # noqa: S323 -- Exact local native fixture.
        try:
            client.login(owner, PASSWORD)
            client.select("INBOX")
            status, found = client.search(None, "SUBJECT", subject)
            if status == "OK" and found[0]:
                return
        finally:
            client.logout()
        if time.monotonic() >= deadline:
            raise AssertionError("Actual website/contact-form email did not reach the retained mailbox")
        time.sleep(0.1)


def prepare_due_certificate(domain: str, metadata: dict[str, object]) -> None:
    run(
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=" + domain + "/O=Let's Encrypt",
            "-keyout",
            str(metadata["ssl_key"]),
            "-out",
            str(metadata["ssl_cert"]),
        ]
    )
    perl(
        """my $d=&get_domain_by('dom',$p->{'domain'});my $i=&cert_info($d);
die 'Native ACME fixture is not eligible' if !&is_acme_cert($i);
die 'Native ACME fixture is not due' if &parse_notafter_date($i->{'notafter'})-time()>2*86400;
print 'PRAHO_NATIVE_MAIL={}';""",
        {"domain": domain},
    )


def exercise_emitters(domain: str, metadata: dict[str, object], *, suffix: str) -> set[str]:
    user = "inbox" + suffix
    run(
        [
            VMIN,
            "create-user",
            "--domain",
            domain,
            "--user",
            user,
            "--pass",
            PASSWORD,
            "--real",
            "Native mailbox fixture",
        ]
    )
    run([VMIN, "modify-user", "--domain", domain, "--user", user, "--real", "Updated fixture", "--send-update-email"])
    perl(
        r"""my $d=&get_domain_by('dom',$p->{'domain'});&lock_domain($d);$d=&get_domain($d->{'id'},undef,1);
$d->{'quota'}=1;$d->{'bw_limit'}=1;$d->{'bw_notify'}=0;$d->{'quota_notify'}='';$d->{'letsencrypt_email_master'}=1;
$d->{'letsencrypt_email'}=0; # An old restored owner flag must not reopen the ACME customer branch.
$d->{'letsencrypt_renew'}=1;$d->{'letsencrypt_last'}=0;delete $d->{'letsencrypt_first_failure'};
&save_domain($d);&unlock_domain($d);my $bw=&get_bandwidth($d);$bw->{'web_'.int(time()/86400)}=1000000;
&save_bandwidth($d,$bw);my $app=$d->{'home'}.'/public_html/native-app';&make_dir($app,0755);
my @scripts=&list_domain_scripts($d);if(!@scripts){&add_domain_script($d,'phpmyadmin','0.1',{path=>$app},'Native old application fixture','/native-app');}
my @up=&list_script_upgrades([$d]);die 'Native app fixture has no genuine version upgrade' if !@up;
&save_module_config_keys({last_letsencrypt_mass_renewal=>0});
&foreign_require('status');my @ids;for my $m (&status::list_services()) {next if $m->{'virtualmin'} ne $d->{'id'};
$m->{'fails'}=1;$m->{'nosched'}=0;if($m->{'type'} eq 'http'){$m->{'host'}='127.0.0.1';$m->{'port'}=9;$m->{'ssl'}=0;}
&status::save_service($m);push @ids,$m->{'id'};}
print 'PRAHO_NATIVE_MAIL=',JSON::PP->new->canonical->encode({ids=>\@ids});""",
        {"domain": domain},
    )
    prepare_due_certificate(domain, metadata)
    run(["/usr/bin/perl", "/usr/share/webmin/virtual-server/quotas.pl"])
    run(["/usr/bin/perl", "/usr/share/webmin/virtual-server/bw.pl", domain])
    run(["/usr/bin/perl", "/usr/share/webmin/virtual-server/scriptwarn.pl"])
    for backup in [metadata["backup"], *metadata["backup_extra"]]:
        run(["/usr/bin/perl", "/usr/share/webmin/virtual-server/backup.pl", "--id", str(backup)], timeout=180)
    perl("&apply_letsencrypt_cert_renewals();print 'PRAHO_NATIVE_MAIL={}';")
    monitor = ["/usr/bin/perl", "/usr/share/webmin/status/monitor.pl", "--force"]
    run(monitor)
    run([VMIN, "modify-domain", "--domain", domain, "--email", "changed@native-mail.example.invalid"])
    run(monitor)
    return {
        "new_users",
        "updated_users",
        "quota_warnings",
        "bandwidth_warnings",
        "bandwidth_actions",
        "backup_owners",
        "acme_owners",
        "application_warnings",
        "status_monitors",
    }


def assert_operator_controls(sink: MailSink) -> None:
    missing = sorted(name for name, recipient in OPERATORS.items() if recipient not in sink.attempts)
    assert not missing, "Native operator positive controls did not attempt their expected sends: " + ", ".join(missing)


def verify_os_warning_refusal(request: dict[str, object]) -> None:
    """Actual root configuration/refusal proof; no quota binary or kernel fixture is invoked."""
    from praho_hosting_node import os_quota_notification_inventory  # noqa: PLC0415 -- Installed production helper.

    assert os_quota_notification_inventory()[0], "Use a fresh fixture with the supported disabled stock OS route"
    defaults = Path("/etc/default/quota")
    original = defaults.read_bytes() if defaults.exists() else None
    original_mode = defaults.stat().st_mode & 0o777 if original is not None else None
    protected = [Path("/etc/webmin/virtual-server/config"), Path("/usr/share/webmin/virtual-server/feature-ssl.pl")]
    before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in protected]
    try:
        defaults.write_text('run_warnquota="true"\nRPCRQUOTADOPTS=\n')
        defaults.chmod(0o600)
        try:
            run(
                ["/usr/bin/python3", "/usr/local/lib/praho/praho_hosting_node.py", "handover"],
                payload=json.dumps(request),
            )
        except AssertionError as error:
            assert "OS quota warning route" in str(error), error
        else:
            raise AssertionError("Enabled OS customer warnings were accepted as Platform-owned")
        assert not Path("/var/lib/praho/hosting/notification-owner").exists()
        assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in protected] == before
    finally:
        if original is None:
            defaults.unlink()
        else:
            defaults.write_bytes(original)
            defaults.chmod(original_mode)
    assert os_quota_notification_inventory()[0]


def handover_with_archive(request: dict[str, object], archived: dict[str, object], sink: MailSink) -> dict[str, object]:
    verify_os_warning_refusal(request)
    run(["/usr/bin/python3", "/usr/local/lib/praho/praho_hosting_node.py", "handover"], payload=json.dumps(request))
    sink.attempts.clear()
    return restore_after_handover(archived, sink)


def post_handover_proofs(sink: MailSink) -> dict[str, object]:
    from praho_hosting_node import (  # noqa: PLC0415 -- Installed fixed production sources.
        ACME_MASTER_BRANCH,
        _reserved_probe_id,
    )

    adapter = ["/usr/bin/perl", "/usr/local/lib/praho/praho-notification-policy.pl", "reserve_probe"]
    reserved = json.loads(run(adapter))
    assert json.loads(run(adapter)) == reserved
    assert reserved == {"uid": _reserved_probe_id(), "gid": _reserved_probe_id()}
    provenance = Path("/var/lib/praho/hosting/probe-identity.json")
    original_provenance = provenance.read_bytes()
    try:
        provenance.unlink()
        try:
            run(adapter)
        except AssertionError as error:
            assert "no isolated probe provenance" in str(error)
        else:
            raise AssertionError("Preexisting NSS identity was accepted without protected provenance")
    finally:
        provenance.write_bytes(original_provenance)
        provenance.chmod(0o600)
    domains = perl("""my @d=grep {$_->{'letsencrypt_renew'} && $_->{'letsencrypt_email_master'}} &list_domains();
die 'Exact native ACME fixture missing' if @d!=1;print 'PRAHO_NATIVE_MAIL=',JSON::PP->new->encode({domain=>$d[0]->{'dom'}});""")
    path = Path("/usr/share/webmin/virtual-server/feature-ssl.pl")
    original = path.read_text()
    assert original.count(ACME_MASTER_BRANCH) == 1
    try:
        for corrected in (False, True):
            path.write_text(original if corrected else original.replace(ACME_MASTER_BRANCH, ""))
            perl(
                """my $d=&get_domain_by('dom',$p->{'domain'});&lock_domain($d);$d=&get_domain($d->{'id'},undef,1);
$d->{'letsencrypt_last'}=0;delete $d->{'letsencrypt_first_failure'};&save_domain($d);&unlock_domain($d);
&save_module_config_keys({last_letsencrypt_mass_renewal=>0});print 'PRAHO_NATIVE_MAIL={}';""",
                domains,
            )
            sink.attempts.clear()
            perl("&apply_letsencrypt_cert_renewals();print 'PRAHO_NATIVE_MAIL={}';")
            assert (OPERATORS["acme"] in sink.attempts) is corrected
            assert CUSTOMER not in sink.attempts
    finally:
        path.write_text(original)
    return {"master_branch_revert_proven": True, "reserved_probe_identity_verified": True}


def fixture_payload() -> dict[str, object]:
    payload = json.load(sys.stdin)
    run_id = payload["run"]
    if (
        os.geteuid() != 0
        or str(UUID(run_id)) != run_id
        or not Path("/var/lib/virtualmin-lab/mixed-configured").exists()
    ):
        raise ValueError("The dedicated full-mail fixture is required")
    return payload


def main() -> None:
    payload = fixture_payload()
    sink = MailSink()
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    try:
        configure_sink(sink.server_address[1])
        if payload.get("post_handover") is True:
            print(json.dumps(post_handover_proofs(sink), sort_keys=True))
            return
        assert not Path("/var/lib/praho/hosting/notification-owner").exists(), "Use a fresh fixture after handover"
        stem = "m776" + uuid4().hex[:8]
        domain, owner = stem + ".praho.test", stem
        create_domain(domain, owner)
        metadata = prepare_permissive_source(domain)
        identity = unix_identity(owner)
        assert_retained_services(owner, domain, PASSWORD, identity)
        retained = mailbox_contents(owner)
        archived = archive_before_handover(stem)
        baseline = stem + "b.praho.test"
        create_domain(baseline, stem + "b", template=str(metadata["template"]), notify=True)
        assert CUSTOMER in sink.attempts, "Permissive native signup did not reproduce a customer send attempt"
        protected = {
            path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
            for path in ("/etc/postfix/main.cf", "/etc/postfix/master.cf", "/etc/dovecot/dovecot.conf")
        }
        before = hashlib.sha256(Path("/etc/webmin/virtual-server/config").read_bytes()).hexdigest()
        inspected = json.loads(
            run(
                ["/usr/bin/python3", "/usr/local/lib/praho/praho_hosting_node.py", "inspect"],
                payload=json.dumps({"identity": "a" * 64}),
            )
        )
        assert not all(inspected["notifications"]["emitters"].values())
        assert hashlib.sha256(Path("/etc/webmin/virtual-server/config").read_bytes()).hexdigest() == before
        verify_resource_only_policy(domain, sink)
        token = str(uuid4())
        request = {"identity": "a" * 64, "token": token, "operator_emails": sorted(OPERATORS.values())}
        archive_proof = handover_with_archive(request, archived, sink)
        created = stem + "c.praho.test"
        create_domain(created, stem + "c", template=str(metadata["template"]), notify=True)
        tested = exercise_emitters(domain, metadata, suffix="one") | {"domain_signup"}
        assert len(tested) == 10 and "status_monitors" in tested
        # Restored-domain metadata enters the production repair hook under the same native domain lock.
        perl(
            """my $d=&get_domain_by('dom',$p->{'domain'});&lock_domain($d);$d=&get_domain($d->{'id'},undef,1);
$d->{'letsencrypt_email'}=0;&save_domain($d);require '/usr/local/lib/praho/praho-notification-policy.pl';
&praho_enforce_domain_notifications($d);&save_domain($d);&unlock_domain($d);print 'PRAHO_NATIVE_MAIL={}';""",
            {"domain": domain},
        )
        run(["/usr/bin/python3", "/usr/local/lib/praho/praho_hosting_node.py", "fence"], payload=json.dumps(request))
        assert_retained_services(owner, domain, PASSWORD, identity)
        contact_form(owner, domain, Path(str(metadata["home"])))
        assert retained.issubset(mailbox_contents(owner)), (
            "Existing mailbox contents changed during native mail handover"
        )
        assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in protected.items())
        assert run(["/usr/bin/systemctl", "is-active", "postfix", "dovecot"]).splitlines() == ["active", "active"]
        customer_attempts = [address for address in sink.attempts if address not in OPERATORS.values()]
        assert not customer_attempts, "A native customer emitter attempted a send after Platform handover"
        assert_operator_controls(sink)
        proof = {
            "native_customer_attempts": len(customer_attempts),
            "operator_attempts": len(sink.attempts),
            "operator_emitters_verified": sorted(OPERATORS),
            "retained_mail": True,
            "contact_form_mail": True,
            "existing_mail_preserved": True,
            "read_only_import": True,
            "resource_policy_preserves_native_warnings": True,
            "emitters_exercised": sorted(tested),
            "native_kernel_proof": False,
            "os_quota_configuration_refusal": True,
            "scheduled_explicit_recipients_verified": True,
            "old_acme_owner_flag_suppressed_before_repair": True,
            "pre_handover_archive_restore": archive_proof,
        }
        print(json.dumps(proof, sort_keys=True))
    finally:
        sink.shutdown()
        sink.server_close()


if __name__ == "__main__":
    main()
