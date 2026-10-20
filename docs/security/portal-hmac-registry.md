# Per-portal HMAC credential registry (#277)

## What this closes

The Portal→Platform HMAC middleware historically verified every request with a single shared
`PLATFORM_API_SECRET` regardless of the `X-Portal-Id` header, and trusted that header (which
keys nonce dedup and rate-limit buckets). A holder of the shared secret could rotate
`X-Portal-Id` per request to mint an unlimited number of throttle/nonce buckets.

The registry resolves the verifying secret **by portal id** and rejects unregistered ids.

## Deployed-service requirements

Production and staging require `PORTAL_HMAC_MODE=enforce` and a non-empty
`PORTAL_HMAC_CREDENTIALS` registry on Platform, and `PORTAL_HMAC_SECRET` on every Portal.
Startup rejects fallback modes, missing/blank credentials, malformed registries and keys
shared between different Portal IDs. Shared-key compatibility remains available explicitly
in development and tests. The signer also refuses an empty cached credential.

The registry is JSON: `{"portal-001": "<secret>"}` or a rotation keyring such as
`{"portal-001": ["<new>", "<previous>"]}`. Each keyring accepts at most three secrets.
Use a distinct randomly generated key for every Portal and register its exact `PORTAL_ID`.

Supported production Compose files require and forward `PORTAL_HMAC_CREDENTIALS` to Platform
and `PORTAL_HMAC_SECRET` to Portal; Platform defaults to enforcement. Native deployment commands
forward the registry and mode, while Portal commands receive only their own signing key.
The production/staging environment examples name the required variables without secret values.

## Coordinate the upgrade and rotation

Provision matching keys before starting services on this release. On the preceding release,
which already supports registry keyrings and per-Portal signing, a coordinated transition is:

1. Generate a distinct new key for each Portal. Add it to that Portal's Platform keyring
   alongside its previous key, and wait for every Platform instance to accept the registry.
2. Set each Portal's `PORTAL_HMAC_SECRET` and roll all instances. Confirm authenticated requests
   succeed for each registered Portal ID.
3. After old requests and retries have drained, remove previous shared keys. Ensure different
   Portal IDs do not share any remaining key. Set Platform to `enforce` everywhere.
4. Start this release with the prepared enforced registry and matching Portal credentials.

Subsequent rotations use the same add-key, roll-signer, remove-old-key sequence with distinct
keys for that Portal. Before rolling a Portal back to an old key, restore that key to its
Platform keyring. No endpoint or signature-format change is required.

## Development compatibility

Outside production/staging, `legacy` verifies the shared `PLATFORM_API_SECRET`; `audit` tries
registered keys and logs successful shared-key fallback; `enforce` uses registered keys only.
An absent per-Portal key may use a valid shared development secret. Empty or non-string signing
secrets are always configuration errors. These compatibility modes are unavailable to deployed
production/staging services.

## Secret strength

Generate secrets with ≥256 bits of randomness, e.g.
`python -c "import secrets; print(secrets.token_urlsafe(32))"`.

## Notes

- The HMAC surface is `/api/` only. The portal's payment endpoints
  (`/api/billing/create-payment-intent/`, `/api/billing/confirm-payment/`,
  `/api/billing/stripe-config/`) live there like every other portal-facing endpoint; nothing
  under `/billing/` is HMAC-gated, because those are staff pages.
- Billing API tests and E2E requests use signed HMAC requests and active customer memberships;
  the view layer has no authentication bypass setting.
