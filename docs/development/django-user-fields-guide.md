# User Fields and Authorization

PRAHO's Platform uses an email-based `User` model derived from Django's `AbstractUser`.
Staff privileges and customer-company membership are separate. A person can have both.

The source of truth is [User and UserManager](../../services/platform/apps/users/models.py)
and the [authorization helpers](../../services/platform/apps/common/decorators.py).
[ADR-0024](../ADRs/ADR-0024-user-role-clarification.md) preserves an unimplemented proposal:
neither `system_role` nor `admin_role` is a current field.

## Django Flags and the Staff Role

| Field | Meaning in PRAHO |
|---|---|
| `is_active` | Whether Django's authentication backend accepts the account. The configured backend also rejects an inactive user when loading a session. |
| `is_staff` | A Django flag that also makes PRAHO's broad `is_staff_user` check true. It does not grant a specific business role. |
| `is_superuser` | Used by Django permission checks and explicitly accepted by PRAHO's administrative and financial helpers. It is separate from `is_staff`. |
| `staff_role` | Internal business role: `admin`, `support`, `billing`, `manager`, or `""` for no staff role. |

Django admin is disabled in [Platform URL configuration](../../services/platform/config/urls.py).
There is no `/admin/` interface to unlock by setting `is_staff`; staff use PRAHO's own views.

`UserManager.create_user()` defaults a missing or `None` staff role to `""` and rejects
unsupported values such as `"customer"`. The `user_staff_role_valid` database constraint
also rejects unsupported stored values, including writes that bypass the manager.
The field is blankable, not nullable.

`create_superuser()` defaults `is_staff=True`, `is_superuser=True` and `staff_role="admin"`.
It requires both Django flags to be true and respects an explicitly supplied valid role.
Assigning `is_superuser` directly does not automatically change the other fields.

## Staff Classification and Authorization

The broad staff property is exactly:

```python
bool(user.staff_role) or user.is_staff or user.is_superuser
```

It classifies a user; it does not test authentication, active status, or permission for
every staff operation. For example, a support agent is staff but cannot issue a refund.

The following gates live in `apps.common.decorators`. They require authentication and
then apply these rules; `is_superuser` is accepted by every role-specific gate listed.

| Gate or helper | Role rule |
|---|---|
| `staff_required`, `staff_required_strict` | `user.is_staff_user` |
| `admin_required` | `staff_role == "admin"` |
| `billing_staff_required` | `admin`, `billing`, `manager` |
| `billing_staff_api_required` | `can_manage_financial_data(user)`, delegating to `User.can_manage_financial_data`: `admin`, `billing`, `manager` |
| `billing_configuration_required` | `admin`, `billing` |
| `support_staff_required` | `admin`, `support`, `manager` |

`admin_required` delegates to the shared `is_administrator()` predicate: superuser or
`staff_role == "admin"`. The [user list and detail views](../../services/platform/apps/users/views.py)
use the same rule, so support, billing and manager roles cannot browse all user accounts.

`staff_required` redirects an authenticated non-staff user to the dashboard with a message;
`staff_required_strict` returns 403 instead. Both redirect anonymous users to login.
`billing_staff_api_required` returns JSON 401 for an anonymous caller and JSON 403 for a
caller without financial privileges, so API clients do not receive a login page.

With both Django staff flags false, the current role outcomes are:

| `staff_role` | `is_staff_user` | `can_manage_financial_data` | `admin_required` |
|---|---|---|---|
| `admin` | True | True | Allowed |
| `support` | True | False | Refused |
| `billing` | True | True | Refused |
| `manager` | True | True | Refused |
| `""` | False | False | Refused |

A bare `is_staff=True` account with an empty role passes the broad staff check but fails
the financial and admin gates. A regression guard checks that production creation sites
supply a staff role or superuser status; do not use the Django flag alone to provision a
new staff account.

These are the shared gates, not a universal permission matrix. For example,
`can_access_admin_functions()` allows admin and manager roles, while `admin_required`
allows only admin or superuser. [Infrastructure permissions](../../services/platform/apps/infrastructure/permissions.py)
also use explicit Django permission codes for deployment and destructive operations.
A role name does not automatically assign those Django permissions.

## Customer Membership

Customer roles live on `CustomerMembership.role`: `owner`, `billing`, `tech`, and `viewer`.
They apply to one customer organization; they do not grant an internal `staff_role`.

`user.is_customer_user` reports whether customer membership rows exist. It does not select
a customer or prove that a membership is active or permits a particular operation.
`customer_or_staff_required` is similarly a broad entry gate; the view must enforce the
appropriate customer scope and role. Signed Portal APIs must validate the authenticated
user's active membership in the customer named by the request.

A staff account can also hold customer memberships. Do not assume that staff and customer
users are mutually exclusive, or use an account-wide membership boolean as tenant authorization.

## Using the Checks

Use the existing decorator or domain permission helper at the server boundary. Templates can
use the corresponding property to offer the same actions:

```django
{% load i18n %}
{% if user.can_manage_financial_data %}
  <span>{% trans "Financial operations available" %}</span>
{% endif %}
```

A hidden control is presentation only; the endpoint still needs its authorization gate.
Account lockout, object ownership and tenant checks remain separate controls.
When `users.mfa_required_for_staff` is enabled, the [staff MFA policy](../../services/platform/apps/users/mfa.py)
and [enrolment middleware](../../services/platform/apps/common/middleware.py) require an
unenrolled staff session to set up a second factor. Superuser status does not bypass that policy.

## Existing Regression Coverage

- [Staff classification and manager validation](../../services/platform/tests/users/test_staff_role_classification.py)
  cover valid roles, Django-flag fallbacks, superuser defaults and the database constraint.
- [Staff account creation guardrail](../../services/platform/tests/users/test_staff_account_creation_guardrail.py)
  checks production creation sites for bare Django-staff accounts.
- [Order security tests](../../services/platform/tests/orders/test_orders_security.py) exercise the
  financial-role matrix; [refund authorization guardrails](../../services/platform/tests/billing/test_refund_authorization_guardrail.py)
  require a financial gate on refund entry points.
