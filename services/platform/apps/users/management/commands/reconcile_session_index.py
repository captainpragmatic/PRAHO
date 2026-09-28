"""Reconcile sessions after draining workers that use the old session backend."""

from django.core.management.base import BaseCommand
from django.utils.translation import gettext as _

from apps.users.tasks import reconcile_session_index


class Command(BaseCommand):
    help = _("Reconcile the session index after draining old workers, before relying on session revocation.")

    def handle(self, *args: str, **options: object) -> None:
        result = reconcile_session_index()
        self.stdout.write(
            self.style.SUCCESS(_("Indexed %(indexed)s sessions; pruned %(pruned)s orphaned index rows.") % result)
        )
