# Virtualmin sub-server as the account hostname: lab contract

Evidence for ADR-0061, plan task P1.0 (second attempt). The alias design was disproved on Virtualmin 8.3
(`virtualmin-account-alias-contract.md`). The owner then chose to test a sub-server of the customer's domain,
with its own web root mapped to the customer's content, and accepted that the account name's certificate lands
in the customer's backups because it is a per-name Let's Encrypt certificate that expires.

## Verdict

**The sub-server design holds on Virtualmin 8.3**, with four conditions PRAHO must meet:

1. The sub-server's `public_html` is replaced by a **relative symlink** `../../public_html` to the customer's
   web root. No Virtualmin program can do this (see S2), so it is one node-side step.
2. Suspend and unsuspend pass **`subservers`** to `disable-domain` and `enable-domain`. Without it the account
   name keeps serving the customer's site while the customer domain shows the disabled page.
3. A backup that must carry the account name passes **`parent`** to `backup-domain`, and the restore names the
   account name as its own `restore-domain` call, **after** the customer's domain.
4. The account name gets a **per-name certificate**, never the wildcard: a sub-server's key is in the
   customer's backup (S5), and a wildcard key there would cover every customer's account name.

| Property | Result | Evidence |
|---|---|---|
| S1: its own `<VirtualHost>` on 80 and 443, `ServerName` = account name | **PROVEN** | generated `sites-available/<name>.conf`, own cert paths, own PHP-FPM pool |
| S2: serves the customer's content, PHP as the customer's user | **PROVEN** (symlink) | marker before and after the mapping; `get_current_user()` = customer |
| S3: suspend and unsuspend follow the customer | **PROVEN with `subservers`**, **fails without** | disabled page on both names, then the site again |
| S4: its own certificate by SNI, key root-only | **PROVEN** | SNI fingerprints differ; `ssl.key` 0600 root; the customer's user is denied |
| S5: the customer's backup carries it; restore recreates it | **PROVEN with `parent` and a second restore call** | 16 archive members; same cert fingerprint and symlink after restore |
| S6: a migration A to B keeps it | **PROVEN at node level** | archive restored on vm-a: content, PHP, cert and mapping intact |
| S7: deleting the customer removes it | **PROVEN** | "Deleting sub-server ..." ; vhost, cert dir, home and unix user gone |
| S7b: deleting only the sub-server never touches the customer's site | **PROVEN** | 589 files, same tree hash before and after |
| S8: listing marker | **PROVEN** | `Type: Sub-server`, `Parent domain: <customer>` |
| Let's Encrypt | **not testable in the lab** | no public DNS; the account zone points the name at the node, so HTTP-01 or DNS-01 works in production |

## Environment

- Run: 2026-10-17 08:23 to 08:29 UTC (the nodes' clock)
- Nodes: vm-a and vm-b (containers `vmlab-a`, `vmlab-b`), image `praho-virtualmin-lab:8.3.0`, `deploy/virtualmin-lab/`
- webmin 2.670, webmin-virtual-server 8.3.0-1-gpl, virtualmin-config 8.3.0-1, apache2 2.4.68-1~deb12u1,
  OpenSSL 3.0.22, Debian GNU/Linux 12 (bookworm)
- Customer domain: `subparent.praho.test` (unix user `subparent`), created with
  `--unix --dir --web --ssl --default-features`; `public_html/marker.txt` holds `parent-marker-<epoch>`
- Account name: `h7k3p2q9.acct.praho.test` (label `[a-z0-9]{8}` under the lab zone `acct.praho.test`)
- Both nodes had no domains before the run and none after it; the unix user and the test files were removed.

The trap recorded in the alias contract still applies: with several vhosts, a request for an unknown name is
served by the first one Apache loaded. The checks below use a marker that differs between the two web roots,
SNI fingerprints, and the generated configuration, never a bare 200.

## S1: its own VirtualHost

```text
$ virtualmin create-domain --domain h7k3p2q9.acct.praho.test --parent subparent.praho.test --desc "account hostname" --web --ssl
A website cannot be enabled unless a home directory is created
$ virtualmin create-domain --domain h7k3p2q9.acct.praho.test --parent subparent.praho.test --desc "account hostname" --dir --web --ssl
... All done!
$ grep -nE "VirtualHost|ServerName|DocumentRoot|SSLCertificate|SetHandler" /etc/apache2/sites-available/h7k3p2q9.acct.praho.test.conf
1:<VirtualHost *:80>
2:    ServerName h7k3p2q9.acct.praho.test
7:    DocumentRoot /home/subparent/domains/h7k3p2q9.acct.praho.test/public_html
32:        SetHandler proxy:unix:/run/php/17922254023240.sock|fcgi://127.0.0.1
35:<VirtualHost *:443>
36:    ServerName h7k3p2q9.acct.praho.test
69:    SSLCertificateFile /etc/ssl/virtualmin/17922254023240/ssl.combined
70:    SSLCertificateKeyFile /etc/ssl/virtualmin/17922254023240/ssl.key
```

`dir` is required with `web`. The sub-server also gets `ServerAlias www.`, `mail.`, `webmail.` and `admin.`
lines for its name; they are harmless because no DNS record exists for them.

## S2: serving the customer's content

The sub-server's own root is `/home/<user>/domains/<name>/public_html`. Three ways to point it at the customer's
`/home/<user>/public_html` were tried:

| Mechanism | Result |
|---|---|
| `modify-web --document-dir ../../../public_html` | refused: `Document directory cannot contain ..` (`modify-web.pl` also refuses a leading `/`) |
| `create-redirect --path / --alias /home/subparent/public_html/` | `Alias / ...` written, but **403** (`AH01630: client denied by server configuration`): the sub-server's vhost grants only its own directories |
| replace `public_html` with a symlink | **works** |

```text
before the mapping: sub=sub-own-marker parent=parent-marker-1792225388
$ cd /home/subparent/domains/h7k3p2q9.acct.praho.test && mv public_html public_html.own \
    && ln -s ../../public_html public_html && chown -h subparent:subparent public_html
after the mapping:  sub=parent-marker-1792225388
php via the account name: php-user=subparent uid=1001 host=h7k3p2q9.acct.praho.test
                          docroot=/home/subparent/domains/h7k3p2q9.acct.praho.test/public_html
                          file=/home/subparent/public_html/who.php
```

The vhost has `Options +SymLinksIfOwnerMatch`; the link and its target are both owned by the customer's user,
so Apache follows it. PHP runs through the sub-server's own FPM pool as the customer's user. The link survived
`modify-web --php-fpm-mode ondemand`, `modify-web --fix-options`, `modify-domain --pass` on the customer domain,
a backup and restore, and a restore on another node, and `validate-domains --all-features` reports
`All features are good`. An absolute link also works; the relative one survives a different home base.

## S3: suspend follows the customer only with `subservers`

```text
$ virtualmin disable-domain --domain subparent.praho.test
sub:    200 parent-marker-1792225388         <- still serving the customer's site
parent: 200 <!doctype html>...               <- the disabled page
$ virtualmin enable-domain --domain subparent.praho.test

$ virtualmin disable-domain --domain subparent.praho.test --subservers
sub (list-domains): Disabled: Manually
sub:    200 <!doctype html>...               <- the disabled page, static and PHP alike
$ virtualmin enable-domain --domain subparent.praho.test --subservers
Enabling virtual server subparent.praho.test ..
Enabling virtual server h7k3p2q9.acct.praho.test ..
sub:    200 parent-marker-1792225388
```

## S4: its own certificate

```text
$ openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=h7k3p2q9.acct.praho.test" ... -keyout acct.key -out acct.crt
$ virtualmin install-cert --domain h7k3p2q9.acct.praho.test --cert /root/sublab/acct.crt --key /root/sublab/acct.key
SNI h7k3p2q9.acct.praho.test: subject=CN = h7k3p2q9.acct.praho.test   sha256 75:15:4B:0B:AC:01:C7:F4...
SNI subparent.praho.test:     subject=CN = *.subparent.praho.test      sha256 A8:29:AE:EF:9F:BC:86:53...
-rw------- 1 root root 1704 /etc/ssl/virtualmin/17922254023240/ssl.key
$ su -s /bin/sh subparent -c 'cat .../ssl.key'   ->   Permission denied
```

At creation the sub-server got a self-signed certificate (no Let's Encrypt in the lab). `install-cert` reads
the certificate and key from files on the node, so PRAHO must place them there first (the plan's temporary
vars-file pattern, `no_log`).

## S5: backup and restore

```text
$ virtualmin backup-domain --domain subparent.praho.test --dest .../parent-only.tar.gz --all-features --no-differential
members naming the sub-server: 0
$ virtualmin backup-domain --domain subparent.praho.test --parent --dest .../with-parent.tar.gz --all-features --no-differential
Creating backup for virtual server h7k3p2q9.acct.praho.test ..
Creating backup for virtual server subparent.praho.test ..
members naming the sub-server: 16 (dir.tar, web, web_pool, ssl, ssl_cert, ssl_key, virtualmin_ssl_key, ...)
the customer's dir.tar: no domains/ entries (nothing is stored twice)
the sub-server's dir.tar: lrwxrwxrwx ./public_html -> /home/subparent/public_html, plus public_html.own/
```

The sub-server's key is in the customer's archive (`_ssl_key`, `_virtualmin_ssl_key`). The owner accepted that
for a per-name Let's Encrypt certificate; it rules out installing a wildcard on the account name.

```text
$ virtualmin delete-domain --domain subparent.praho.test          (S7)
$ virtualmin restore-domain --domain subparent.praho.test --source .../with-parent.tar.gz --all-features
domains: subparent.praho.test                                     <- only what was named
$ virtualmin restore-domain --domain h7k3p2q9.acct.praho.test --source .../with-parent.tar.gz --all-features
domains: subparent.praho.test h7k3p2q9.acct.praho.test
Type: Sub-server   Parent domain: subparent.praho.test
content: parent-marker-1792225388   SNI sha256 75:15:4B:0B:AC:01:C7...   public_html -> /home/subparent/public_html
```

## S6: across nodes

The `--parent` archive from vm-b, copied to vm-a and restored there (customer domain first, then the account
name), served the customer's content and PHP as the customer's user, with the same certificate fingerprint and
the same symlink. PRAHO's migration today backs up and restores only the account's domain
(`migration_backup_params`, `restore_domain_params`) and disables and enables it without `subservers`.

## S7: deleting

```text
$ virtualmin delete-domain --domain subparent.praho.test
Deleting virtual server subparent.praho.test ..
    Deleting sub-server h7k3p2q9.acct.praho.test ..
vhosts naming h7k3: 0   /home/subparent: absent   /etc/ssl/virtualmin/: empty   id subparent: no such user

(on vm-a, deleting only the account name)
customer's public_html before: 589 files, tree sha256 377ec0663831b19b
$ virtualmin delete-domain --domain h7k3p2q9.acct.praho.test
    Deleting home directory ..
customer's public_html after:  589 files, tree sha256 377ec0663831b19b; the customer domain still serves its marker
```

Deleting the sub-server removes its own home and does not follow the symlink.

## S8: how it lists

`list-domains --multiline --domain <name>` shows `Type: Sub-server` and `Parent domain: <customer>`, its own
`Home directory` and `HTML directory`, and `Features: dir web ssl logrotate`. Every listing PRAHO reads must
tell these rows from customer domains (the plan's P1.6).

The 8.x JSON listing (`list-domains --multiline --json`) carries the same marker as `values.type =
["Sub-server"]` and `values.parent_domain = ["<customer>"]`; a customer domain has `type = ["Top-level server"]`.

## S9: an in-place restore of the customer's own backup

A backup of the customer domain alone (no `parent`), restored over the live customer domain while the
sub-server exists, kept the sub-server, its symlink and its site (`h7k3p2q9...` still listed, link
`../../public_html` intact, HTTP 200). So an ordinary customer restore does not need to know about the
account name; only a restore that recreates the customer domain from nothing does.

## Side finding

With several vhosts on a node, a request whose `Host` matches no vhost is answered by the first loaded one.
`h7k3p2q9...` sorts before `subparent...`, so after S1 an unknown name returned the customer's content through
the account name's vhost. This is not new (whichever customer domain sorts first gets it today), but account
names are opaque and many, so a node should serve a neutral default site first. Recorded for the plan.

## S10: creating the child under a disabled customer domain

`create-domain --parent` under a customer domain disabled with `--subservers` created the child **enabled**:
`list-domains` showed no `Disabled:` line and the account name answered 200 (with the child's own default
page, since the link was not yet in place). A disabled parent does not disable a new child, so PRAHO must
disable the child itself whenever the account is suspended or the node copy is a migration target that is
not yet active, before the link exposes the customer's files.

## S11: a customer replacing the web root

Test accounts `subparent` and `otheracct`; commands run as `subparent` (the customer), not root.

```text
id www-data: groups=33(www-data),1004(subparent),1005(otheracct)      <- Apache can read every customer's home
/home/otheracct and its public_html: drwxr-x--- otheracct:otheracct
PHP-FPM pools: no open_basedir set

account name, link repointed by the customer at /home/otheracct/public_html:  static secret.txt  OTHER-SECRET [200]
                                                                              PHP o.php          404
account name, link repointed at /etc:                                          /hostname          vm-b.praho.test [200]
the customer's OWN site, a nested link to the other account (public_html/peek): refused (Apache error page)
the customer's OWN site, public_html renamed and replaced by a link to otheracct: secret.txt     OTHER-SECRET [200]
the customer's OWN site, public_html replaced by a link to /etc:                 /hostname       vm-b.praho.test [200]
the customer's PHP reading the other account's file directly:                    Permission denied
```

`SymLinksIfOwnerMatch` guards links below the document root, not the document root itself. So any customer who
can write their own home can already swap their **own** site's root for another customer's web files or `/etc`
and read them through Apache, because `www-data` belongs to every customer's group. The account name's link
adds no capability a customer does not have today; it is one more root of the same kind. The weakness is in
the node's present setup, independent of this design, and needs its own decision (for example a root-owned,
customer-immutable web-root path, or Apache no longer in customer groups). PHP is not affected: it runs as
the customer, who cannot read other homes. The lab node runs no FTP service; customer file access paths were
not part of this run.

## Remote API forms

All the programs are on PRAHO's allowlist already. Over `remote.cgi` a bare flag is an empty value, as in the
other contracts: `program=create-domain&domain=<name>&parent=<customer>&dir=&web=&ssl=&desc=...`,
`program=disable-domain&domain=<customer>&subservers=`, `program=enable-domain&domain=<customer>&subservers=`,
`program=backup-domain&domain=<customer>&parent=&...`, `program=restore-domain&domain=<name>&source=...`,
`program=install-cert&domain=<name>&cert=<path>&key=<path>`, `program=delete-domain&domain=<name>`.
The contract suite records the real responses when these parameter sets are added.

## Reproduce

On a node with no domains (`docker exec vmlab-b ...`):

```text
virtualmin create-domain --domain subparent.praho.test --user subparent --pass <pw> --desc "sub parent" --unix --dir --web --ssl --default-features
virtualmin create-domain --domain h7k3p2q9.acct.praho.test --parent subparent.praho.test --dir --web --ssl
cd /home/subparent/domains/h7k3p2q9.acct.praho.test && mv public_html public_html.own && ln -s ../../public_html public_html && chown -h subparent:subparent public_html
openssl req -x509 ... ; virtualmin install-cert --domain h7k3p2q9.acct.praho.test --cert <abs> --key <abs>
virtualmin disable-domain / enable-domain --domain subparent.praho.test [--subservers]           (S3)
virtualmin backup-domain --domain subparent.praho.test [--parent] --dest <file> --all-features --no-differential
virtualmin delete-domain --domain subparent.praho.test ; virtualmin restore-domain --domain <each, customer first> --source <file> --all-features
```
