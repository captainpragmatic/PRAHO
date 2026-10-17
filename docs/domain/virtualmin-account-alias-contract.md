# Virtualmin alias domain as the account hostname: lab contract

Evidence for ADR-0061, plan task P1.0. The plan proposed carrying the account hostname
(`<label>.<zone>`, for example `h7k3p2q9.acct.praho.test`) as a Virtualmin alias domain with its own web
and ssl features, so that it would have its own Apache `<VirtualHost>` and its own certificate.

This document was written by hand from commands run by hand against lab node vm-b. It is not generated.
To refresh it, repeat the commands under "Reproduce".

## Verdict

**The design is DISPROVEN on Virtualmin 8.3.** An alias domain never has a virtual host or a certificate of
its own. Points (1) and (2) are false, and the plan's rule applies: stop there, no fallback is designed here,
and the decision goes back to the owner.

Points (3) to (7) were still observed, and they are recorded below. They were run after the gating
disproof, so none of them rescues the design.

| Question | Verdict | Reason |
|---|---|---|
| Q1: `create-domain --alias` with web and ssl creates its own `<VirtualHost>` on 80 and 443 | **DISPROVEN** | `--ssl` is refused for an alias; with `--web` the alias names are added as `ServerAlias` lines to the parent's two `<VirtualHost>` blocks. The code path has no switch |
| Q2: A certificate can be installed on the alias alone; SNI for the account name serves it while the customer domain keeps its own | **DISPROVEN** | `install-cert` on the alias fails (it has no certificate directory); SNI for the alias name serves the parent's certificate. The only way to serve the wildcard for that name is to install it on the parent, which replaces the customer's own certificate |
| Q3: Requests to the alias name serve the customer domain's content | **PROVEN, moot** | The alias names sit in the parent's vhost, so they share its document root. By default Virtualmin adds a redirect to the parent (302), so `--no-alias-redirect` is needed |
| Q4: The parent's backup and restore carry the alias | **DISPROVEN** | The archive has no alias member. After deleting the parent, the alias is gone too, and a restore of the parent brings back only the parent. The restored SSL vhost keeps stale alias `ServerAlias` lines |
| Q5: Disabling the parent disables the alias, enabling restores it | **PROVEN in effect, moot** | The alias names share the parent's vhost, so the disabled page is served on them. The alias row itself is never marked disabled |
| Q6: No Let's Encrypt request for the alias at creation | **PROVEN, moot** | Virtualmin's creation-time request skips aliases in code (`!$dom->{'alias'}`), and an alias cannot have the ssl feature. The controls are the template's `ssl_auto_letsencrypt` and `create-domain --acme-never` |
| Q7: Key isolation: the wildcard key is root-only, unreadable as the domain user, and absent from the customer's backup | **DISPROVEN** | The key file is root 0600 in a root 0700 directory, and the domain user cannot read it. But the wildcard has to be installed on the parent to be served, and then its key is in the customer's own backup archive, twice |

Also recorded (needed by plan task P1.6):
- an alias row is marked `Type: Alias` (multiline) or `values.type == ["Alias"]` (JSON), with `real_domain`;
- `list-domains` has `--no-alias` and `--alias <parent>` filters.

## Environment

- Run: 2026-10-14 22:34 to 22:41 UTC (the node's clock)
- Node: vm-b.praho.test (container `vmlab-b`), image `praho-virtualmin-lab:8.3.0`, Docker lab in `deploy/virtualmin-lab/`
- virtualmin-config 8.3.0-1
- webmin 2.670
- webmin-virtual-server 8.3.0-1-gpl
- Apache/2.4.68 (Debian)
- OpenSSL 3.0.22
- os: Debian GNU/Linux 12 (bookworm)
- Parent domain: `aliasparent.praho.test` (unix user `aliasparent`), created with `--unix --dir --web --ssl --default-features`
- Alias: `h7k3p2q9.acct.praho.test` (label `[a-z0-9]{8}` under the lab zone `acct.praho.test`)
- Node state before the run: no domains. After the run: no domains, `sites-enabled` empty, `/etc/ssl/virtualmin/` empty, no `aliasparent` unix or MariaDB user, the self-signed wildcard and the archives deleted.

## A trap in the lab: one vhost is every vhost

On a node with a single name-based virtual host, Apache serves that host for any `Host` header. A control
request for a name that exists nowhere gets the customer's content:

```text
$ curl -sk -i --resolve nosuchname.example.test:443:127.0.0.1 https://nosuchname.example.test/marker.txt
HTTP/2 200
parent-marker-1792017300
```

So "the alias name returned the customer's page" proves nothing on its own here. The checks below rely on the
generated Apache configuration (`ServerName` and `ServerAlias` lines), on a redirect that the configuration
causes, and on SNI handshakes that return a distinguishable certificate. Where a curl result is cited, it is
labelled as not discriminating.

## Q1: Does the alias get its own VirtualHost (80 and 443)?

**DISPROVEN**: `--ssl` is refused for an alias; with `--web` the alias names are added as `ServerAlias` lines to the parent's `<VirtualHost>` blocks. No second block is created.

1. The exact request from the plan, with web and ssl:

```text
$ virtualmin create-domain --domain h7k3p2q9.acct.praho.test --alias aliasparent.praho.test --desc "account hostname" --web --ssl
--ssl option makes no sense for alias servers
```

The same refusal comes back over remote.cgi (`program=create-domain&domain=h7k3p2q9.acct.praho.test&alias=aliasparent.praho.test&web=&ssl=`).

2. With `--web` only, the alias is created with the single feature `web`:

```text
$ virtualmin create-domain --domain h7k3p2q9.acct.praho.test --alias aliasparent.praho.test --desc "account hostname" --web
...
Updating origin virtual server ..
Performing other Apache configuration ..
Applying webserver configuration ..
All done!

$ virtualmin list-domains --multiline --domain h7k3p2q9.acct.praho.test
    Type: Alias
    Real domain: aliasparent.praho.test
    Home directory: /home/aliasparent/domains/h7k3p2q9.acct.praho.test
    HTML directory: /home/aliasparent/public_html
    Features: web
    Website hostnames: aliasparent.praho.test www.aliasparent.praho.test ... h7k3p2q9.acct.praho.test www.h7k3p2q9.acct.praho.test mail.h7k3p2q9.acct.praho.test webmail.h7k3p2q9.acct.praho.test admin.h7k3p2q9.acct.praho.test
    SSL candidate hostnames: h7k3p2q9.acct.praho.test
    SSL cert used by: webmin
```

3. Apache has one virtual host per port, both for the parent. The alias names are `ServerAlias` lines inside them:

```text
$ apache2ctl -S
*:80                   aliasparent.praho.test (/etc/apache2/sites-enabled/aliasparent.praho.test.conf:1)
*:443                  aliasparent.praho.test (/etc/apache2/sites-enabled/aliasparent.praho.test.conf:54)

$ ls /etc/apache2/sites-available
000-default.conf  aliasparent.praho.test.conf  default-ssl.conf

$ grep -n 'ServerName\|ServerAlias h7k3p2q9' /etc/apache2/sites-available/aliasparent.praho.test.conf
2:    ServerName aliasparent.praho.test
7:    ServerAlias h7k3p2q9.acct.praho.test
... (the same on the 443 block)
```

4. Why: in `/usr/share/webmin/virtual-server/feature-web.pl`, `setup_web` has two branches. For `if ($d->{'alias'})` it writes `ServerAlias` into the parent's vhosts (port 80 and, if the parent has ssl, the ssl port) and sets `alias_mode = 1`. Only the `else` branch adds a `<VirtualHost>`. There is no setting that selects the second for an alias.

5. Closing probe: enabling ssl on the alias after creation is a silent no-op.

```text
$ virtualmin enable-feature --domain h7k3p2q9.acct.praho.test --ssl
Updating server h7k3p2q9.acct.praho.test ..
    Updating Webmin user ..
    .. done
.. done
Re-loading Webmin ..
.. done
(exit 0)

$ virtualmin list-domains --multiline --domain h7k3p2q9.acct.praho.test | grep Features
    Features: web
$ ls /etc/ssl/virtualmin/
1792017281229864            <- the parent only
```

## Q2: Can a certificate be installed on the alias alone?

**DISPROVEN**: `install-cert` on the alias fails, SNI for the alias name serves the parent's certificate, and installing the wildcard on the parent replaces the customer's own certificate for the customer name.

1. A self-signed wildcard made on the node (root 0600, `umask 077`):

```text
$ openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout /root/aliaslab/wild.key -out /root/aliaslab/wild.crt \
    -subj "/CN=*.acct.praho.test" -addext "subjectAltName=DNS:*.acct.praho.test,DNS:acct.praho.test"
```

2. `install-cert` on the alias, with absolute file paths (relative paths are read as empty data):

```text
$ virtualmin install-cert --domain h7k3p2q9.acct.praho.test --cert /root/aliaslab/wild.crt --key /root/aliaslab/wild.key
Installing new SSL files ..
Failed to open /etc/ssl/virtualmin/1792017312230710/ssl.cert for writing : No such file or directory
Error
(exit 1)
```

The alias has no certificate directory, because it has no ssl feature (Q1). `list-certs --domain <alias>` answers "None of the specified virtual servers have an SSL cert".

3. SNI handshakes before anything is installed. Both names get the parent's own certificate, because both names are in the same vhost:

```text
$ echo | openssl s_client -connect 127.0.0.1:443 -servername h7k3p2q9.acct.praho.test 2>/dev/null | openssl x509 -noout -subject
subject=CN = *.aliasparent.praho.test
$ echo | openssl s_client -connect 127.0.0.1:443 -servername aliasparent.praho.test 2>/dev/null | openssl x509 -noout -subject
subject=CN = *.aliasparent.praho.test
```

4. The only way to make the alias name serve the wildcard is to install it on the parent. Then both names serve it, so "the customer domain keeps its own" is false:

```text
$ virtualmin install-cert --domain aliasparent.praho.test --cert /root/aliaslab/wild.crt --key /root/aliaslab/wild.key
$ echo | openssl s_client ... -servername h7k3p2q9.acct.praho.test ... | openssl x509 -noout -subject
subject=CN = *.acct.praho.test
$ echo | openssl s_client ... -servername aliasparent.praho.test ... | openssl x509 -noout -subject
subject=CN = *.acct.praho.test
```

## Q3: Do requests to the alias name serve the customer's content?

**PROVEN, moot**: the alias names are in the parent's vhost, so they share its document root. Without `--no-alias-redirect` they are redirected to the parent instead.

1. The default (`web_aliasredir=1` in the module config) adds a rewrite to the parent. This is configuration, not a default-vhost effect, so it is discriminating:

```text
$ grep -n 'RewriteCond %{HTTP_HOST} (www' -A1 /etc/apache2/sites-available/aliasparent.praho.test.conf
    RewriteCond %{HTTP_HOST} (www\.)?h7k3p2q9\.acct\.praho\.test
    RewriteRule ^/(?!\.well-known)(.*)$ http://aliasparent.praho.test/ [R]            (port 80)
    RewriteRule ^/(?!\.well-known)(.*)$ https://aliasparent.praho.test/ [R]           (port 443)

$ curl -sk -i --resolve h7k3p2q9.acct.praho.test:80:127.0.0.1 http://h7k3p2q9.acct.praho.test/marker.txt
HTTP/1.1 302 Found
Location: http://aliasparent.praho.test/
```

2. With `--no-alias-redirect` (`list-domains` then shows `Redirect alias domain: No`), the rewrite is absent and the alias name answers 200 with the parent's `marker.txt`. As the trap above says, this curl result alone does not discriminate; the document root is the parent's because the names are in the parent's vhost (Q1 step 3, `HTML directory: /home/aliasparent/public_html`).

## Q4: Do the parent's backup and restore carry the alias?

**DISPROVEN**: the archive has no alias member, deleting the parent deletes the alias, and a restore of the parent leaves no alias row.

1. PRAHO's standalone flags (`dest`, `all-features`, `no-differential`) on the parent, with the alias present:

```text
$ virtualmin backup-domain --domain aliasparent.praho.test --dest /root/aliaslab/bk/parent.tar.gz --all-features --no-differential
Creating backup for virtual server aliasparent.praho.test ..
...
Creating final backup archive ..
$ tar -tzf parent.tar.gz | sed 's/^\.\/aliasparent.praho.test_//' | tr '\n' ' '
dir.tar virtualmin_plan unix logrotate web_elog mysql web virtualmin virtualmin_ssl_cert web_alog virtualmin_ssl_key
virtualmin_ssl_ca virtualmin_scripts webmin_url virtualmin-awstats mysql_aliasparent ssl_ca ssl ssl_cert web_pool
ssl_key webmin.tar unix_url
$ grep -c h7k3p2q9 parent.tar.gz.dom
0
```

Only the `_ssl` member (a copy of the parent's ssl vhost) and the AWStats configuration mention the alias name.

2. Delete the parent (the alias goes with it), then restore:

```text
$ virtualmin delete-domain --domain aliasparent.praho.test
.. deleted
$ virtualmin list-domains --name-only
(empty: the alias is gone too)
$ virtualmin restore-domain --domain aliasparent.praho.test --source /root/aliaslab/bk/parent.tar.gz --all-features
Restore completed successfully.
$ virtualmin list-domains --name-only
aliasparent.praho.test
```

3. After the restore, the port 80 block has no alias names; the port 443 block still has them, with no alias domain behind them (the archive's `_ssl` member is a copy of the ssl vhost, and it holds these lines, step 1):

```text
$ grep -n 'ServerAlias.*h7k3p2q9' /etc/apache2/sites-enabled/0-aliasparent.praho.test.conf
48:    ServerAlias h7k3p2q9.acct.praho.test
49:    ServerAlias www.h7k3p2q9.acct.praho.test
50:    ServerAlias mail.h7k3p2q9.acct.praho.test
51:    ServerAlias webmail.h7k3p2q9.acct.praho.test
52:    ServerAlias admin.h7k3p2q9.acct.praho.test
```

The port 80 block (lines 1 to 41) has none. The restored vhost file is also renamed (`0-aliasparent.praho.test.conf`). The half-state is stale names on 443 and none on 80.

## Q5: Does disabling the parent disable the alias, and enabling restore it?

**PROVEN in effect, moot**: the disabled page is served for the alias names, because they share the parent's vhost. The alias row is not marked disabled.

```text
$ virtualmin disable-domain --domain aliasparent.praho.test        (over remote.cgi: program=disable-domain)
$ list-domains (JSON, multiline)
aliasparent.praho.test   ['Top-level server']  disabled= ['Manually']
h7k3p2q9.acct.praho.test ['Alias']             disabled= None
$ grep -c 'ServerAlias h7k3p2q9' /etc/apache2/sites-enabled/*.conf
2                                                          (names still in the vhost)
$ curl -sk https://<each name>/marker.txt
(an HTML page on both names, not marker.txt; /home/aliasparent/public_html/index.html now carries the notice
 "This page is not delivered by Virtualmin ... a disabled site")
$ virtualmin enable-domain --domain aliasparent.praho.test
$ curl -sk https://<each name>/marker.txt
parent-marker-1792017300                                   (both names; the disabled page was the discriminating result)
```

## Q6: Is a Let's Encrypt request attempted for the alias at creation?

**PROVEN, moot**: no request is attempted. The evidence is the code path, because the lab's `.test` names are names no CA can validate, so a request there would fail whether or not Virtualmin made it.

1. The creation-time request lives in `/usr/share/webmin/virtual-server/virtual-server-lib-funcs.pl` (~9090):

```perl
if ($dom->{'auto_letsencrypt'} && &domain_has_website($dom) &&
    !$dom->{'disabled'} && !$dom->{'alias'} && !$dom->{'ssl_same'} &&
    &under_public_dns_suffix($dom->{'dom'})) {
```

   `!$dom->{'alias'}` excludes aliases. The other post-creation trigger, `feature-ssl.pl` (~249, `create_initial_letsencrypt_cert`), runs from `setup_ssl`, which an alias never reaches (Q1).
2. The alias creation output (Q1 step 2) has no certificate, ACME or Let's Encrypt step. `/var/webmin/miniserv.error` and `/var/webmin/webmin.log` have no `acme` or `letsencrypt` lines.
3. The controls, for the parent and for any future domain that has ssl:
   - template setting `ssl_auto_letsencrypt` (UI: "Request certificate from provider at domain creation"; unset in the lab's "Default Settings");
   - `create-domain --acme-never` (alias `--letsencrypt-never`), `--acme` and `--acme-always`;
   - the request also requires `under_public_dns_suffix`, which `.test` fails, so the lab cannot show a request for a parent either;
   - the module config has `auto_letsencrypt=1`; its role was not traced.

## Q7: Key isolation

**DISPROVEN**: the key file is protected, but the key ends up in the customer's own backup.

1. Permissions of what Virtualmin writes for the parent's certificate (the same before and after installing the wildcard):

```text
drwx------ 2 root root 4096 /etc/ssl/virtualmin/1792017281229864/
-rw------- 1 root root 1704 ssl.key        (the wildcard, after install-cert on the parent)
-rw------- 1 root root 1200 ssl.cert
-rw------- 1 root root 2402 ssl.combined
-rw------- 1 root root 4107 ssl.everything
$ su -s /bin/sh aliasparent -c 'cat /etc/ssl/virtualmin/*/ssl.key'  ->  denied
```

The on-disk key is root-only and the domain's unix user cannot read it. That half of the requirement holds.

2. The customer's own backup of the parent (`backup-domain --domain aliasparent.praho.test --all-features --no-differential`), after the wildcard was installed on the parent:

```text
$ tar -tzf parent2.tar.gz | grep -i key
./aliasparent.praho.test_virtualmin_ssl_key
./aliasparent.praho.test_ssl_key
$ for each member: openssl pkey -in <member> -pubout | sha256sum | cut -c1-16
aliasparent.praho.test_ssl_key             f9e7a22ba42fbd3b
aliasparent.praho.test_virtualmin_ssl_key  f9e7a22ba42fbd3b
wild.key (the wildcard)                    f9e7a22ba42fbd3b
```

The wildcard private key is in the customer's archive twice. The archive is what Platform fetches and stores for the customer, and what a restore, a migration and a support download can expose. The key can only be kept out of it by not installing the wildcard on the parent, and then the alias name does not serve it (Q2).

## For PRAHO's code

### How an alias row is marked in `list-domains`

| Form | Alias row | Other rows |
|---|---|---|
| `--multiline` text | `Type: Alias`, and `Real domain: <parent>` | `Type: Top-level server` |
| `multiline=&json=1`, `values` | `"type": ["Alias"]`, `"real_domain": ["<parent>"]`; also `redirect_alias_domain`, `home_directory` of the form `<parent home>/domains/<alias>` | `"type": ["Top-level server"]`, no `real_domain` |
| `name-only` | the alias is listed by name, with no marker | |
| `--no-alias` (`no-alias=` over remote.cgi) | excluded | kept (checked with `multiline=&json=1`) |
| `--alias <parent>` (`alias=<parent>`) | lists only that parent's aliases | |

The row also has `"features": ["web"]` and the username of the parent. PRAHO's `SNAPSHOT_ATTRIBUTES` (`virtualmin_migration_service.py`) does not include `Type`, so the marker is dropped before any filter can see it.

### remote.cgi parameters that worked

Sent to `https://<node>:10000/virtual-server/remote.cgi?program=<name>&...`. A bare flag is an empty value (`web=`), as in the incremental contract.

| Operation | Parameters | Result |
|---|---|---|
| create the alias | `program=create-domain&domain=h7k3p2q9.acct.praho.test&alias=aliasparent.praho.test&web=&no-alias-redirect=&desc=account+hostname` | works, `Features: web`, `Redirect alias domain: No` |
| the same with `ssl=` | `...&web=&ssl=` | refused: `--ssl option makes no sense for alias servers` |
| delete the alias | `program=delete-domain&domain=h7k3p2q9.acct.praho.test` | works |
| list with row detail | `program=list-domains&multiline=&json=1` (add `&domain=<name>`) | has `type` and `real_domain` |
| list without aliases | `program=list-domains&multiline=&json=1&no-alias=` | works |
| aliases of a parent | `program=list-domains&multiline=&json=1&alias=<parent>` | works |
| disable and enable the parent | `program=disable-domain&domain=<parent>`, `program=enable-domain&domain=<parent>` | work |

`name-only=` together with `json=1` returns rows with empty `values`, so it cannot carry the marker.

## What this means for the plan (facts only; the decision is the owner's)

- The plan's design correction ("an alias with its own web and ssl features, proven in P1.0") is false on 8.3.
- Tasks written on that premise cannot be built as written:
  - P1.4 `ensure_node_alias` and `remove_node_alias`;
  - P1.5 (alias parameter validation);
  - the alias steps of P1.7;
  - P1.10 "every alias receives the current certificate".
- P1.6 does not depend on the design. If any alias rows exist (for example a customer's own alias domains), the marker above is what it needs, and it should be read from the raw row before `SNAPSHOT_ATTRIBUTES` drops it.
- The ADR's premise stands: one vhost serves one certificate (see the plan's own correction). The lab shows that a Virtualmin alias does not escape it.

## Reproduce

All commands run on vm-b (`docker exec vmlab-b ...`), which must have no domains:

```text
virtualmin create-domain --domain aliasparent.praho.test --user aliasparent --pass <pw> --desc "alias parent" --unix --dir --web --ssl --default-features
virtualmin create-domain --domain h7k3p2q9.acct.praho.test --alias aliasparent.praho.test --web --no-alias-redirect
apache2ctl -S ; ls /etc/apache2/sites-available ; grep -n 'ServerAlias' /etc/apache2/sites-enabled/*.conf
openssl req -x509 ... (Q2 step 1) ; virtualmin install-cert --domain <alias|parent> --cert <abs path> --key <abs path>
virtualmin backup-domain / delete-domain / restore-domain (Q4) ; disable-domain / enable-domain (Q5)
```

Clean-up: delete the alias, then the parent, then remove the files under `/root/aliaslab`.
