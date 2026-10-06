# HTTPS Deployment Checklist

Use this for every production or staging deploy that serves PRAHO publicly. Both services run
behind Caddy, each on its own hostname: `PORTAL_DOMAIN` (customers) and `PLATFORM_DOMAIN` (staff,
API and webhooks). Most of the HTTPS hardening is fixed in code and config. This checklist is mostly
about **verifying** it, not rolling it out step by step.

Commands below use these shell variables. Set them to your real hostnames first:

```bash
PORTAL_HOST=portal.example.com
PLATFORM_HOST=platform.example.com
```

---

## How TLS is arranged

Nothing in this table is an operator decision. It tells you what to expect when you verify.

| Concern | Where it lives | What ships |
|---|---|---|
| TLS termination and certificates | Caddy: `deploy/caddy/Caddyfile` (Docker), `deploy/ansible/roles/praho-native/templates/Caddyfile.native.j2` (native) | Automatic ACME certificates per hostname, contact address `ACME_EMAIL` |
| HTTP → HTTPS redirect | Caddy | Django's own redirect stays **off**: every shipped compose file and the Ansible env template set `DJANGO_SECURE_SSL_REDIRECT=false`. Set it to `true` only if Django faces the internet directly |
| Scheme Django sees | `SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")` in both services' `config/settings/prod.py` | Caddy sends `X-Forwarded-Proto` |
| HSTS | **Behind Caddy, the edge owns it**: every Caddy config sends `HSTS_POLICY`, and replaces the header Django sends. Without an edge, Django's `SECURE_HSTS_*` settings apply | Production: unset, so `max-age=31536000; includeSubDomains`. Staging: `HSTS_POLICY=max-age=3600` (`.env.example.staging`; the Docker Ansible role derives it from `praho_env`). Nothing preloads |
| Secure cookies | `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE` are `True` in both `prod.py` files | Not configurable |
| Allowed hosts and CSRF origins | `ALLOWED_HOSTS` environment variable (comma-separated) | `CSRF_TRUSTED_ORIGINS` is derived as `https://<host>` for each host. Startup fails if `ALLOWED_HOSTS` is unset or contains `*`. The platform also refuses to start without `PORTAL_DOMAIN` and `PLATFORM_DOMAIN` |
| Staff UI exposure | Caddy's `@staff` matcher | The platform's staff UI is served only to `PLATFORM_ALLOWED_CIDRS` (native: `platform_allowed_ips`); everyone else gets `403 Access denied`. `/api/*`, the webhook endpoints and unsubscribe links stay public |
| Content Security Policy | `apps/common/middleware.py` in each service | `default-src 'self'`, with no third-party hosts: every script, style and font is self-hosted. The portal sends `Content-Security-Policy-Report-Only` instead when `CSP_REPORT_ONLY=true`; production should enforce |

> **Production HSTS is permanent for a year.** A browser that has seen the header refuses plain
> HTTP to that host for a year, and lowering `HSTS_POLICY` later only takes effect on each
> browser's next visit. Confirm HTTPS works on **both** hostnames before the first deploy that
> serves them publicly. Staging uses one hour precisely so a broken rollout can be undone.

> **How `HSTS_POLICY` reaches Caddy.**
> - Each site sets it twice: in the deferred `header` block, which replaces Django's header, and
>   on an immediate `header` line, which covers responses Caddy generates itself (a 502 with the
>   upstream down).
> - **Set but empty would send an empty header, which turns HSTS off.** So every compose file and
>   both Ansible roles repeat the non-empty default.
> - **Quote a value that contains `;`** (for example, adding `; preload`). `source .env`, Docker
>   Compose and the native template all strip the double quotes.
> - **Upgrading an existing staging deployment:** Compose falls back to the one-year default when
>   `HSTS_POLICY` is missing, so add `HSTS_POLICY=max-age=3600` to the staging `.env`. Native
>   deploys fall back to one hour on their own when `praho_env` is `staging`.
>
> A staging host under a parent domain that sends `includeSubDomains` still inherits the parent's
> longer policy. To preload a domain, submit it at hstspreload.org and add `; preload` to its
> production policy; nothing preloads by default.

---

## Before the first HTTPS deploy

- [ ] **DNS.** Both `PORTAL_DOMAIN` and `PLATFORM_DOMAIN` resolve to the server.
- [ ] **Environment.** `.env` sets `PORTAL_DOMAIN`, `PLATFORM_DOMAIN`, `ACME_EMAIL`, `ALLOWED_HOSTS`
      and `PLATFORM_ALLOWED_CIDRS`. The comments in `.env.example.prod` explain each.
- [ ] **Ports.** 80 and 443 are reachable from the internet, so Caddy can complete the ACME
      challenge. The single-server compose file publishes 80, 443 and 443/udp.
- [ ] **Redirect setting.** `DJANGO_SECURE_SSL_REDIRECT=false`, as shipped. Caddy owns the redirect.

---

## Verify after every deploy

### 1. Certificates
Run this for both hosts:

```bash
openssl s_client -connect "$PORTAL_HOST:443" -servername "$PORTAL_HOST" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

- [ ] The subject matches the hostname, the issuer is the ACME CA, and the certificate is in date.

### 2. Health over HTTPS

```bash
curl -fsS "https://$PORTAL_HOST/status/"            # {"status": "healthy", "service": "portal"}
curl -fsS "https://$PLATFORM_HOST/api/users/health/"
```

- [ ] Both return 200. `deploy/scripts/health-check.sh` checks the same endpoints, and is installed at
      `/opt/praho/scripts/health-check.sh` on native hosts.

### 3. HTTP redirects to HTTPS

```bash
curl -sI "http://$PORTAL_HOST/"   | grep -i '^location'
curl -sI "http://$PLATFORM_HOST/" | grep -i '^location'
```

- [ ] Each one redirects to the `https://` URL of the same host.

### 4. Security headers

```bash
curl -sI "https://$PORTAL_HOST/login/" | grep -iE \
  '^(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy):'
```

Repeat with `https://$PLATFORM_HOST/auth/login/` from an address in `PLATFORM_ALLOWED_CIDRS`. From
anywhere else, that request correctly returns 403.

- [ ] `Strict-Transport-Security` is exactly the environment's policy, sent once: production
      `max-age=31536000; includeSubDomains`, staging `max-age=3600`.
- [ ] `Content-Security-Policy` starts `default-src 'self'` and names no third-party host. If only
      `Content-Security-Policy-Report-Only` appears, `CSP_REPORT_ONLY` is on and the policy is not
      being enforced.
- [ ] `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and a `Referrer-Policy` are all present.

### 5. Cookie flags

```bash
curl -sI "https://$PORTAL_HOST/login/" | grep -i '^set-cookie'
```

- [ ] Every `Set-Cookie` carries `Secure`. The session cookie (`portal_session` on the portal), which
      is set once you log in, also carries `HttpOnly`.

Read the headers directly. `curl -c` writes a cookie-jar file, and that file records neither the
`SameSite` attribute nor the word `Secure`.

### 6. Django deployment checks
- **Portal.** It runs `manage.py check --deploy --fail-level ERROR` before every start: the native
  unit does it as `ExecStartPre`, and the container entrypoint does it too. So a running portal has
  already passed. Its warnings are in `journalctl -u praho-portal`, or in
  `docker compose -f deploy/docker-compose.single-server.yml logs portal`.
- **Platform.** Run the check by hand. Native:

  ```bash
  cd /opt/praho/src/services/platform
  sudo -u praho bash -c 'set -a && source /opt/praho/.env && set +a && \
    PYTHONPATH=$PWD /opt/praho/.venv-linux/bin/python manage.py check --deploy'
  ```

  Docker:

  ```bash
  docker compose -f deploy/docker-compose.single-server.yml exec platform python manage.py check --deploy
  ```

- [ ] No errors are reported, and every warning has been read and understood.

### 7. Tests

The HTTPS settings behaviour is covered in CI by `HTTPSSecurityConfigurationTest` in
`services/platform/tests/common/test_common_security.py`. To run it locally:

```bash
make test-file FILE=tests.common.test_common_security
```

Never run tests with production settings or against the production database.

---

## Rollback

- **Application.** Run `make rollback VERSION=vX.Y.Z`, which calls `deploy/scripts/rollback.sh`. To
  restart in place on a native host: `sudo systemctl restart praho-platform praho-portal praho-qcluster`.
- **HTTPS itself cannot be rolled back.** Browsers that have seen the HSTS header keep refusing HTTP
  for up to a year, and no setting shortens that. Fix forward.
- **Certificates.** Caddy renews automatically. If issuance or renewal fails, read Caddy's log:
  `journalctl -u caddy` on native hosts, `docker compose -f deploy/docker-compose.single-server.yml
  logs caddy` under Docker.

---

## Where the logs are

| | Native | Docker |
|---|---|---|
| Service output | `journalctl -u praho-platform`, `-u praho-portal`, `-u praho-qcluster` | `docker compose -f deploy/docker-compose.single-server.yml logs -f platform portal` |
| Application log files | Platform: `/var/log/praho/app.log`, `security.log`, `error.log`. Portal: `/var/log/praho/portal/app.log`, `error.log` | The same paths, inside each container |
| Caddy access logs | `/var/log/caddy/portal-access.log`, `/var/log/caddy/platform-access.log` | `/data/portal-access.log`, `/data/platform-access.log` in the Caddy container |

---

## External checks

- [ ] **SSL Labs** for both hosts: `https://www.ssllabs.com/ssltest/analyze.html?d=<host>`. Target A or A+.
- [ ] **Mozilla HTTP Observatory** for both hosts: `https://developer.mozilla.org/en-US/observatory`.

## Ongoing

- Caddy renews certificates on its own. Alert on certificate expiry anyway, because a failed renewal
  is silent until the certificate lapses.
- Review the CSP and security headers when the front-end adds an asset source.
- Track Django security releases.

---

**Checklist completed by**: _________________ **Date**: _________________

**Reviewed by**: _________________ **Date**: _________________
