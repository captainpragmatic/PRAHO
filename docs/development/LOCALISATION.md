# Localisation settings and consumers

The Business → Localisation settings group controls the staff platform and
customer portal web interfaces (issue #380). The catalog remains the source of
truth and all five keys have production readers under ADR-0042.

| Key | Default | Consumer |
| --- | --- | --- |
| `system.default_language` | `en` | Web language selection and inherited profile language |
| `system.default_country` | `RO` | New customer, registration, company, and address forms |
| `system.timezone` | `Europe/Bucharest` | Web timestamp conversion |
| `system.staff_date_format` | `%d.%m.%Y` | Staff web dates |
| `system.customer_date_format` | `%d.%m.%Y` | Customer portal web dates |

Languages are English and Romanian. Countries use the existing Babel territory
data and timezones use the installed IANA database. Date settings accept only
DD.MM.YYYY, YYYY-MM-DD, DD/MM/YYYY, and MM/DD/YYYY. Times use a 24-hour clock;
operational timestamps retain seconds where they were previously displayed.

## Romanian catalog workflow

A PR that adds or changes translatable strings must include their reviewed Romanian
translations and compiled catalogs. The three catalog pairs are:

- `services/platform/locale/ro/LC_MESSAGES/django.po` and `.mo`
- `services/portal/locale/ro/LC_MESSAGES/django.po` and `.mo`
- `shared/ui/locale/ro/LC_MESSAGES/django.po` and `.mo`

Install GNU gettext before using extraction, full lint or translation tests. On macOS,
run `brew install gettext` and ensure its binaries are on `PATH`; on Debian/Ubuntu,
run `sudo apt-get install gettext`. The existing virtual environment from `make install`
supplies Django, polib and the test dependencies.

```sh
make i18n-extract
make translate TRANSLATE_ARGS=--include-fuzzy
# Review i18n-review-*.yaml: edit msgstr_suggested and set reviewed entries to status: approved.
make translate-diff
make translate-apply
make i18n-compile
make i18n-check
make test-i18n
```

Generation supplies suggestions for review; approve only translations checked against
the current source and context. Keep the catalog's terminology and formal address,
every placeholder and markup fragment, and all three Romanian plural forms. Do not
replace an existing non-fuzzy translation merely because extraction moved its references.
The apply tool patches entries in place and protects existing translations. Review files
are local working files; include the resulting `.po` and `.mo` changes in the PR.

`make i18n-check` calls `scripts/translate_po.py check`, the read-only gate also run by full
`make lint`. It captures the current working tree, including untracked source files, and
runs compilation, extraction and guards in a unique temporary directory. It validates the
captured originals first, so stale `.mo` files fail before temporary compilation can mask
them. It checks messages, contexts, translations, plural forms and `Plural-Forms`, then
compares fresh extraction semantically; timestamps, references, comments and ordering do
not cause drift failures. Gettext versions can infer different format-marker flags;
these do not change runtime messages and are ignored in extraction comparisons.
Placeholder content, GNU format checks and fuzzy status are validated independently.
For literal percent examples, put `# xgettext:no-python-format` immediately before
the first translated string literal: inside a multiline gettext call, or before
a call whose literal is on the same line. Earlier assignments or string arguments
can consume the comment. This prevents older gettext releases from treating text
such as `% or` as a format placeholder.
Missing tools, incomplete or fuzzy translations, format errors,
guard failures and inputs changing during inspection fail with diagnostics. Repository
files remain unchanged on success and failure; the check has no repair mode.

Use the reported catalog, context, msgid and references to repair the source or reviewed
translation, then compile explicitly and rerun the gate. After incorporating new source
changes, repeat extraction, review and compilation. `make test-i18n-guards` runs only the
borrowed-message and catalog-markup guards; `make test-i18n` adds checker fixtures and
translation-tool tests. The checker invokes the guards alone to avoid recursion, with
pytest coverage and cache output disabled.

## Preferences and compatibility

Existing profile values are preserved. New profiles store empty language,
timezone, and date-format values, meaning **Use system default**. A profile
override wins over the corresponding runtime default. Selecting inheritance
again clears explicit language session/cookie selections. Legacy session
language choices remain honored until the next profile save.

Anonymous visitors use a supported explicit session/cookie language, then browser
language, then the runtime default. Signed-in users following system defaults
use those defaults regardless of browser language. Locale activation is scoped
to the web request and response language headers match the rendered content.

Country labels and new-form defaults follow the active English/Romanian UI language.
Country settings initialize new forms; they do not rewrite existing addresses.
Posted country values and explicit initials win. Creation APIs accept the
country and fall back to the configured default when it is omitted. Partial
updates preserve existing country values. Country-dependent consumers normalize
English/Romanian names and ISO codes through one shared helper before VAT,
validation, and audit decisions. The country setting initializes new addresses;
VAT still uses the actual billing country and tax profile, and existing fiscal
snapshots are preserved.

## Display boundary

Use `{% load localisation_tags %}` and
`{% localised_date value "datetime" %}` for human-facing web dates. The optional
kind is `date` (default), `datetime`, `datetime_seconds`, `time`, `time_seconds`,
or `month_year`; Django's normal `as variable` assignment is supported.

The formatter accepts date/datetime objects and ISO strings from portal APIs.
Aware timestamps are converted explicitly to the display timezone. Plain dates
and naive timestamps are not shifted; invalid/missing input renders empty so a
template can provide its existing placeholder.

No request-wide timezone activation is used. ORM calendar lookups, recurring
billing, registry operations, scheduler clocks, invoice PDFs, and e-Factura keep
their existing rules. Billing/e-Factura pages and embedded invoice/payment dates
retain their existing fixed rendering too. Registry registration/expiry dates,
billing schedules, and scheduler next-run displays also retain their prior formats. Document/API endpoints retain their
prior language policy.
HTML date inputs and machine-readable timestamp attributes retain their wire
formats. Explicit Romanian date utilities remain available for documents.

## Portal propagation

Maintenance windows keep their permitted calendar timezone separate from the viewer's display timezone.
Their signed DTOs carry aware ISO timestamps; Portal and staff templates use the display formatter.
Notice snapshots use the primary active member's display preferences with organisation fallback, and
Romanian/English templates use the customer's locale. No request-wide timezone activation changes
billing or scheduling. See [the maintenance runbook](../deployment/NODE_MAINTENANCE.md).

`POST /api/localisation/` requires the existing HMAC service authentication and
a fresh signed timestamp; customer identity is not required. Its allowlisted
response contains only `default_language`, `default_country`, `timezone`, and
`customer_date_format` under `localisation`, with `success: true`.

The portal caches validated defaults for 60 seconds, scoped to its platform
endpoint and portal ID. Failure retries are spaced 30 seconds apart and use
last-known-good values for up to one hour, then built-in defaults. Failures and
malformed payloads never replace the last-known-good snapshot. Dates within a
request share one resolved policy and cause no individual API calls.

Login and periodic session-validation responses carry optional raw
`localisation_preferences`. Profile saves update the current session immediately;
other sessions refresh on their existing authentication-validation cadence.
Profile reads retain effective language/timezone fields for older clients and
add raw inheritance preferences separately. The portal can read older payloads.
The legacy customer-profile PUT keeps its required, nonblank first/last-name
contract; `/api/users/profile/` supports partial updates with optional names.

Small pure helpers are mirrored across the isolated services with parity tests;
platform settings access and portal API access remain separate.

## Deployment and verification

1. Deploy the platform and apply its migrations.
2. Run `setup_default_settings --category localisation` without `--force`.
   Consumers have catalog fallbacks even before the rows are synced.
3. Deploy the portal. Check the Localisation group, both profile forms, date
   rendering, and country defaults. Allow up to one minute for portal changes.
4. Run settings consumer-contract, profile/API, formatting, cache, country, and
   cross-service parity tests, plus the full lint/test gates. DCO must pass on
   every PR commit and the squash commit must retain its sign-off.

Browser negotiation deliberately uses Django 5.2's bounded Accept-Language parser.
The public request helper falls back to the process-wide `LANGUAGE_CODE`, so it
cannot preserve the runtime-default contract on its own. The isolated import is
covered by mirrored weighted, malformed, oversized-header, and fallback tests;
recheck it when upgrading the pinned Django 5.2 dependency. This avoids maintaining
a separate HTTP parser or changing global settings during a request.

Framework references: [Django language selection](https://docs.djangoproject.com/en/5.2/topics/i18n/translation/#how-django-discovers-language-preference)
and [Django timezone presentation](https://docs.djangoproject.com/en/5.2/topics/i18n/timezones/).

## Browser regression

With the normal isolated E2E services and accounts running, execute:

```sh
make test-e2e-file FILE=tests/e2e/test_localisation.py
```

The parameterized test exercises both services, checks all four date presets,
saves name and language together, switches to Romanian, and returns every
preference to inheritance. It restores the account's original preferences and
name afterward. `PLATFORM_BASE_URL` and `PORTAL_BASE_URL` can point it at alternate
local test ports.

These screenshots use synthetic accounts and changed test defaults (Germany,
UTC, ISO staff dates and US customer dates). A separate year-boundary fixture
confirmed `2025-12-31 22:30 UTC` displays on 1 January in Europe/Bucharest.

![Localisation settings](images/localisation-settings.png)

[Customer profile with inherited defaults](images/localisation-customer-profile.png)
