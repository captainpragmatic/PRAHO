# Per-portal HMAC credential registry (#277)

## What this closes

The Portal→Platform HMAC middleware historically verified every request with a single shared
`PLATFORM_API_SECRET` regardless of the `X-Portal-Id` header, and trusted that header (which
keys nonce dedup and rate-limit buckets). A holder of the shared secret could rotate
`X-Portal-Id` per request to mint an unlimited number of throttle/nonce buckets.

The registry resolves the verifying secret **by portal id** and rejects unregistered ids.

## Modes (`PORTAL_HMAC_MODE`)

| Mode | Behavior |
|---|---|
| `legacy` (default) | Verify against `PLATFORM_API_SECRET` for any well-formed portal id. The registry is ignored. This is the historical behavior — deploying the code changes nothing until you opt in. |
| `audit` | Try the registry keyring first; if it does not verify — id unregistered **or** registered but signing with a secret not in its keyring — fall back to the shared secret and, **only if that fallback succeeds**, log a warning naming the portal id. The two cases get distinct warnings (add the id vs. fix its registration). Audit never causes an outage; a request that fails both is a plain 401, no warning. |
| `enforce` | Registry only. Unregistered portal id → rejected. The signature must verify against one of that portal's own secrets. No shared-secret fallback. Requires a non-empty registry (enforced at startup). |

`PORTAL_HMAC_CREDENTIALS` is JSON: `{"portal-001": "<secret>"}` or, as a keyring for
zero-downtime rotation, `{"portal-001": ["<new>", "<old>"]}` (verified against each; capped
at 3). Malformed JSON / shape fails startup — it never silently degrades to an empty
(vulnerability-restoring) registry.

### Where these are set

The supported Docker Compose files and the Ansible role forward `PORTAL_HMAC_MODE` /
`PORTAL_HMAC_CREDENTIALS` (platform) and `PORTAL_HMAC_SECRET` (portal) from the host `.env`
into the containers. Under compose `${VAR:-}` interpolation an **unset** variable reaches the
container as the **empty string** — the two are indistinguishable — so on both services empty
means "not set": the platform treats an empty registry as unset (legacy/audit unaffected;
`enforce` still requires a non-empty registry), and the portal falls back to
`PLATFORM_API_SECRET`. The "empty is a provisioning error" guard remains only for a
directly-assigned Python setting (e.g. `override_settings` in tests). `PORTAL_HMAC_MODE`
defaults to `legacy` when unset.

## Rollout — zero-downtime, no cross-service secret cutover

Closing the hole does **not** require provisioning a new secret. #277 is an identity-allowlist
property, separable from per-portal secret separation. Register the **existing** secret value
under the real portal id(s):

1. **Deploy** platform + portal on this code. Defaults: `PORTAL_HMAC_MODE=legacy`, registry
   unset, portal `PORTAL_HMAC_SECRET` unset → effective secret is `PLATFORM_API_SECRET` on
   both sides, both deploy orders safe. Zero behavior change.
2. **Audit.** Reconcile the real production portal id(s) against the deployment/config source
   of truth for `PORTAL_ID` (traffic logs alone miss a dormant portal). Set
   `PORTAL_HMAC_CREDENTIALS={"<portal-id>": ["<current PLATFORM_API_SECRET value>"]}` and
   `PORTAL_HMAC_MODE=audit`. Portal unchanged — still verifies. Watch for
   `⚠️ [HMAC Auth] unregistered portal … via shared-secret fallback` warnings; each names a
   portal id you must add before enforcing. A `registered portal … keyring is missing the
   signing secret` warning instead means that id is registered with the wrong secret — fix its
   registration, don't just wait for it to go quiet.
3. **Enforce.** When audit is quiet across **every** platform instance, set
   `PORTAL_HMAC_MODE=enforce`. Unregistered `X-Portal-Id` is now rejected — the bucket-minting
   hole is closed, zero downtime, no new secret.

### Residual property

Registering the same existing secret under the portal id closes unlimited arbitrary-id
minting. It does **not** prevent a holder of that shared secret from authenticating as the one
registered id (they hold its secret). Distinct **cross-portal isolation** comes from the
optional rotation below.

### Optional: rotate to a distinct per-portal secret (enabled by the keyring)

1. Add the new secret `S`: `PORTAL_HMAC_CREDENTIALS={"portal-001": ["S", "<old>"]}`.
2. Wait until **every** platform instance accepts both.
3. Set the portal's `PORTAL_HMAC_SECRET=S` and roll every portal instance.
4. Verify no old-secret traffic remains (through the retry/timestamp horizon), then drop
   `<old>`: `{"portal-001": ["S"]}`.

Rollback ordering: once `<old>` is removed from the platform, do not roll the portal back to
the old secret — that would cause an outage. Re-add `<old>` to the keyring first.

## Secret strength

Generate secrets with ≥256 bits of randomness, e.g.
`python -c "import secrets; print(secrets.token_urlsafe(32))"`.

## Notes

- The billing-API HMAC endpoints (`/billing/create-payment-intent/`, …) share the same
  middleware validator, so they are covered automatically.
- `PORTAL_HMAC_BYPASS` is a test/e2e-only view-layer flag, downstream of and independent from
  this middleware.
