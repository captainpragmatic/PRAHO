# ADR-0030: Rate Limiting Architecture and Single Source of Truth

**Status:** Accepted
**Date:** 2026-03-05
**Authors:** PRAHO Development Team
**Related:** ADR-0017 (portal auth fail-open), ADR-0026 (portal frontend architecture)

## Context

Rate limiting evolved in multiple places:

1. Platform DRF global throttle classes (`DEFAULT_THROTTLE_CLASSES`)
2. Platform per-view throttle classes (`@throttle_classes` and viewset defaults)
3. Portal middleware throttles before Platform API calls

This created drift risk:

- duplicate class definitions (`AuthThrottle` in more than one location)
- stale/unused throttle classes still exported
- throttle rate keys in settings not consumed by live classes
- unclear ownership of traffic routing between HMAC service traffic and direct traffic

## Decision

Adopt a three-layer, explicit rate-limiting model with a single source of truth for Platform throttle rates.

### Layer 1: Platform global DRF throttles

Canonical classes in `apps.common.performance.rate_limiting`:

- `PortalHMACRateThrottle` (`portal_hmac`)
- `PortalHMACBurstThrottle` (`portal_hmac_burst`)
- `CustomerRateThrottle` (`customer`)
- `BurstRateThrottle` (`burst`)

### Layer 2: Platform per-view throttles

Canonical classes also defined in `apps.common.performance.rate_limiting`, re-exported by `apps.api.core.throttling`:

- `StandardAPIThrottle` (`sustained`)
- `BurstAPIThrottle` (`api_burst`)
- `AuthThrottle` (`auth`)

Order-specific scoped throttles remain in `apps.api.orders.views` with explicit scopes.

### Layer 3: Portal middleware throttles

Portal middleware limits request bursts before API calls, including auth and API-path protections.

### Routing and mutual exclusion

HMAC-authenticated requests are identified via `request._portal_authenticated` and routed to portal HMAC throttle scopes.
For those requests, customer/burst fallback classes skip throttling to avoid double-throttling.

### Single source of truth

`REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]` is generated from `THROTTLE_RATES` with only active, consumed scopes:

- `portal_hmac`, `portal_hmac_burst`, `customer`, `burst`
- `auth`, `sustained`, `api_burst`, `anon`
- `order_create`, `order_calculate`, `order_list`, `product_catalog`

### Startup validation

On app startup:

1. rate strings are validated with strict parser rules
2. throttle class import paths are validated
3. each declared `scope` must exist in throttle rates

Misconfiguration fails fast with `ImproperlyConfigured`.

## Consequences

### Positive

- Removes duplicate throttle definitions and dead throttle classes.
- Prevents silent config drift via startup validation and guardrail tests.
- Clarifies ownership between global routing throttles and per-view throttles.
- Keeps Portal behavior predictable during throttling (friendly 429 UX, no 429 auto-retry amplification).

### Negative

- Higher coupling between settings scope keys and throttle class definitions.
- More tests/documentation to maintain.

### Neutral

- No database migration required.
- Existing endpoint contracts remain intact; behavior is clarified and standardized.

## References

- `services/platform/apps/common/performance/rate_limiting.py`
- `services/platform/apps/api/core/throttling.py`
- `services/platform/apps/common/apps.py`
- `services/platform/config/settings/base.py`
- `services/portal/apps/api_client/services.py`
