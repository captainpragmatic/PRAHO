"""Reset a person's two-factor authentication from the server.

The recovery path when no administrator can sign in to reset it from the person's page, for
example a sole administrator who has lost both their authenticator and their backup codes. The
reset is audited as an operator action, and the person's Platform sessions end.

    manage.py reset_two_factor --email someone@example.ro --reason "Lost phone and backup codes"
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction

from apps.users.mfa import MFAService
from apps.users.models import User
from apps.users.services import SessionSecurityService


class Command(BaseCommand):
    help = "Reset a person's two-factor authentication (audited operator action)."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--email", required=True, help="The account to reset.")
        parser.add_argument("--reason", required=True, help="Why, for the audit trail.")

    def handle(self, *args: Any, **options: Any) -> None:
        email = str(options["email"]).strip().lower()
        reason = str(options["reason"]).strip()
        if not reason:
            raise CommandError("Give a reason; it is recorded in the audit trail.")

        with transaction.atomic():
            user = User.objects.select_for_update().filter(email__iexact=email).first()
            if user is None:
                raise CommandError(f"No account with the email {email}.")
            if not user.two_factor_enabled:
                raise CommandError(f"{user.email} has no two-factor authentication to reset.")
            MFAService.disable_totp(user, reason=f"Operator reset: {reason}", by_operator=True)

        SessionSecurityService.invalidate_all_sessions_for_user(user.pk)
        self.stdout.write(f"Two-factor authentication reset for {user.email}; their sessions have ended.")
