"""Session keys shared by recovery views and their rate-limit responses."""

PASSWORD_RESET_SESSION_KEY = "password_reset_credentials"  # noqa: S105 -- session key name, not a credential
REGISTRATION_CONFIRM_SESSION_KEY = "registration_confirm_link"
# What the visitor came to buy, from the operator's site (apps.common.intent), sent with the registration.
REGISTRATION_INTENT_SESSION_KEY = "registration_intent"
# The visit's first UTM tags and referring site, sent with every order.
ATTRIBUTION_SESSION_KEY = "first_touch_attribution"
