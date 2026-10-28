"""Tell people by email when something that protects their account or their company changes (#689).

The notification preferences promise "security alerts (login attempts, 2FA)". The chokepoints
every path goes through (MFAService and apply_password_change) write the notice, so the staff
pages, the Portal's API and the operator command all send it. It goes to the account's own
address, in its language.

A change to a company's team, contact details or legal and tax identity is told to every owner of
the company, the one who made it included: a stolen session acts as the owner, and the owner's
mailbox is where that shows. A role change or a removal is also told to the member, and a new
contact email to the old address. A personal data export request and a revealed gift-card code
are told to the person. Notices name fields, never their values.

A notice is a queued email (notifications.EmailService) written in the transaction that makes the
change: it commits with the change, is never sent for a change that rolled back, and the email
queue delivers it and retries it. It used to be queued only after the commit, and one whose
queueing or whose send failed was lost.

Writing a notice runs in its own savepoint. One that cannot be written is logged and dropped: it
must never undo the change or hide its result, such as recovery codes the person has to see now.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Literal

from django.template.loader import render_to_string
from django.utils import translation
from django.utils.translation import gettext

from apps.common.transactions import best_effort_atomic

from .models import CustomerMembership, User

if TYPE_CHECKING:
    from apps.customers.models import Customer

logger = logging.getLogger(__name__)

SUBJECT_COMPANY_MAX = 80
SecurityNotice = Literal["2fa_enabled", "2fa_disabled", "2fa_reset", "backup_codes", "password_changed"]
TeamNotice = Literal["team_member_added", "team_role_changed", "team_member_removed"]
CompanyNotice = Literal["company_contact_changed", "company_tax_changed"]


def _subject(event: str, context: dict[str, Any]) -> str:
    """The notice's subject, in the active language."""
    name = str(context.get("company", ""))
    # A company name may be 255 characters and a subject only 200: one too long would be refused.
    company = {"company": name if len(name) <= SUBJECT_COMPANY_MAX else name[: SUBJECT_COMPANY_MAX - 1] + "…"}
    subjects = {
        "2fa_enabled": lambda: gettext("Two-factor authentication was turned on"),
        "2fa_disabled": lambda: gettext("Two-factor authentication was turned off"),
        "2fa_reset": lambda: gettext("Two-factor authentication was reset"),
        "backup_codes": lambda: gettext("New backup codes were created"),
        "password_changed": lambda: gettext("Your password was changed"),
        "team_member_added": lambda: gettext("A team member was added to %(company)s") % company,
        "team_role_changed": lambda: gettext("A team role changed in %(company)s") % company,
        "team_member_removed": lambda: gettext("A team member was removed from %(company)s") % company,
        "company_contact_changed": lambda: gettext("The contact details of %(company)s were changed") % company,
        "company_tax_changed": lambda: gettext("The legal or tax details of %(company)s were changed") % company,
        "data_export_requested": lambda: gettext("A copy of your personal data was requested"),
        "gift_card_revealed": lambda: gettext("A gift card code was shown"),
    }
    return subjects[event]()


def _name(user: User) -> str:
    """How a notice greets a person: their first name, else their address."""
    return user.first_name or user.email


def language_of(user: User) -> str:
    """The language a person reads their notices in: theirs, else the platform's default."""
    from apps.common.localisation_services import (  # noqa: PLC0415  # ADR-0007: cross-app, deferred
        get_localisation_defaults,
        user_localisation_preferences,
    )

    return user_localisation_preferences(user).get("preferred_language") or get_localisation_defaults().default_language


def queue_notice(
    to: str, event: str, *, language: str, context: dict[str, Any], customer: Customer | None = None
) -> None:
    """Write one notice as a queued email in the current transaction; never raises."""
    from apps.notifications.services import EmailService  # noqa: PLC0415  # ADR-0007: cross-app, deferred

    with best_effort_atomic(logger=logger, scope="Security", message=f"Notice {event} not written"):
        with translation.override(language):
            context = {**context, "event": event}
            if "fields" in context:  # field labels, in this recipient's language
                context["fields"] = ", ".join(str(label) for label in context["fields"])
            subject = _subject(event, context)
            text_message = render_to_string("users/emails/security_notice.txt", context)
            html_message = render_to_string("users/emails/security_notice.html", context)
        result = EmailService.send_email(
            to=to,
            subject=subject,
            body_text=text_message,
            body_html=html_message,
            customer=customer,
            template_key=f"security_notice:{event}",
            priority="high",
            track_opens=False,
            track_clicks=False,
            async_send=True,
            essential=True,
        )
        if not result.success:
            logger.warning("⚠️ [Security] Notice %s not queued: %s", event, result.error)


def notify_credential_change(
    user_pk: int, event: SecurityNotice, *, actor_email: str = "", by_operator: bool = False
) -> None:
    """Write the notice for a change to the account's own 2FA or password; never raises.

    actor_email names an administrator who acted on someone else's account. by_operator marks
    a reset run from the server's command line, which has no account to name.
    """
    with best_effort_atomic(logger=logger, scope="Security", message=f"Notice {event} not written"):
        user = User.objects.filter(pk=user_pk, is_active=True).select_related("profile").first()
        if user is None:
            logger.info("💡 [Security Notice] Not sent: no active account %s", user_pk)
            return
        context = {"name": _name(user), "actor_email": actor_email, "by_operator": by_operator}
        queue_notice(user.email, event, language=language_of(user), context=context)


def _owners(customer: Customer) -> list[User]:
    memberships = CustomerMembership.objects.filter(
        customer=customer, role="owner", is_active=True, user__is_active=True
    ).select_related("user", "user__profile")
    return [membership.user for membership in memberships]


def _to_people(people: list[User], event: str, context: dict[str, Any], customer: Customer | None) -> None:
    """One notice to each person once, in their own language."""
    seen: set[int] = set()
    for person in people:
        if person.pk in seen:
            continue
        seen.add(person.pk)
        queue_notice(
            person.email,
            event,
            language=language_of(person),
            context={**context, "name": _name(person)},
            customer=customer,
        )


def notify_team_change(  # noqa: PLR0913  # the change, and the member it touched in each role
    customer: Customer, event: TeamNotice, *, actor_email: str, member: User, old_role: str = "", new_role: str = ""
) -> None:
    """Tell the company's owners, and for a role change or a removal the member, about a team change."""
    labels = dict(CustomerMembership.CUSTOMER_ROLE_CHOICES)
    with best_effort_atomic(logger=logger, scope="Security", message=f"Notice {event} not written"):
        people = _owners(customer)
        if event != "team_member_added" and member.is_active:
            people.append(member)
        context = {
            "company": customer.name,
            "actor_email": actor_email,
            "member_email": member.email,
            "role": labels.get(new_role, new_role),
            "old_role": labels.get(old_role, old_role),
            "new_role": labels.get(new_role, new_role),
        }
        _to_people(people, event, context, customer)


def notify_company_changed(customer: Customer, event: CompanyNotice, *, fields: list[Any], old_email: str = "") -> None:
    """Tell the company's owners which fields changed, and the old contact address that it was replaced."""
    from apps.common.localisation_services import get_localisation_defaults  # noqa: PLC0415  # ADR-0007

    with best_effort_atomic(logger=logger, scope="Security", message=f"Notice {event} not written"):
        owners = _owners(customer)
        context = {"company": customer.name, "fields": fields}
        _to_people(owners, event, context, customer)
        if old_email and old_email.casefold() not in {owner.email.casefold() for owner in owners}:
            language = get_localisation_defaults().default_language
            queue_notice(
                old_email, event, language=language, context={**context, "name": customer.name}, customer=customer
            )


def notify_data_export_requested(user: User) -> None:
    """Tell the person that a copy of their personal data was requested from their account."""
    _to_people([user] if user.is_active else [], "data_export_requested", {}, None)


def notify_gift_card_revealed(user: User, code: str) -> None:
    """Tell the person that a gift card's code was shown, naming the card by its last four characters."""
    _to_people([user] if user.is_active else [], "gift_card_revealed", {"last4": code[-4:]}, None)
