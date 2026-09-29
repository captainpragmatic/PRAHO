"""Order errors the PLATFORM emits, declared here so they survive extraction.

localise_platform_error() (see views.py) translates these by looking each received
string up as a msgid. The catalogue entries therefore have to exist in the portal's
own django.po — but `make i18n-extract` runs makemessages against portal source only,
and msgmerge marks any entry it cannot find there as obsolete (`#~ msgid`), which
msgfmt then drops. Without this module the fix silently reverts to English on the next
routine translation-maintenance run, with nothing failing to announce it.

Declaring them here gives makemessages a real source reference to anchor. Nothing
imports the tuple at runtime; extraction is its entire purpose.

The duplication with the platform is deliberate and guarded, not accidental:
tests/integration/test_platform_error_localisation.py derives the platform's message
set from its source and fails if this list drifts in either direction — a message added
there and not here, or one kept here after the platform dropped it.

Interpolated messages are excluded because they CANNOT work here, not because they do
not matter. Their msgid holds a {} template while the portal receives the already
formatted string, so a lookup can never match. Most of them report internal catalogue
inconsistencies a customer could not act on anyway, but that is not true of all of them:
"Item '{}': a domain is required before ordering" is squarely actionable and still
reaches the customer in English. Translating it needs a different mechanism, such as the
platform sending a code or the message being split so the product name is the only
interpolated part. Recorded here so the gap is known rather than assumed away.
"""

from django.utils.translation import gettext_lazy as _

# Keep sorted. Must equal the non-interpolated gettext literals in the platform's
# apps/orders/preflight.py, which the integration test asserts.
PLATFORM_ORDER_ERRORS = (
    _("Failed to validate VAT and totals"),
    _("Order currency not set"),
    _("Please provide a contact email address"),
    _("Please provide a contact name for your order"),
    _("Please provide your city"),
    _("Please provide your country"),
    _("Please provide your county/state"),
    _("Please provide your postal/ZIP code"),
    _("Please provide your street address"),
    _("Romanian business without VAT number - verify tax profile"),
    _(
        "VAT evidence missing for reverse charge; this order cannot be confirmed until "
        "the customer's VAT number is confirmed in VIES"
    ),
)
