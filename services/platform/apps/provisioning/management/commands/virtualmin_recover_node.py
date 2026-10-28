"""Plan or queue backup-based recovery onto a managed replacement node."""

from typing import Any
from uuid import UUID

from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_recovery_service import VirtualminRecoveryService, select_recovery_backups


class Command(BaseCommand):
    help = "Recover a fenced node's accounts from retained backups. Dry-run by default."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--source-server", type=UUID, required=True)
        parser.add_argument("--target-server", type=UUID, required=True)
        parser.add_argument("--apply", action="store_true", help="Queue the verified recovery plan")
        parser.add_argument("--source-fenced", default="", help="Evidence that the old node is powered off or fenced")

    def handle(self, *args: Any, **options: Any) -> None:
        if options["source_server"] == options["target_server"]:
            raise CommandError("Source and target must differ")
        if options["apply"] and not options["source_fenced"].strip():
            raise CommandError("--apply requires --source-fenced evidence; an unreachable node alone is insufficient")
        try:
            source = VirtualminServer.objects.get(pk=options["source_server"])
            target = VirtualminServer.objects.get(pk=options["target_server"])
        except VirtualminServer.DoesNotExist as error:
            raise CommandError("The source or target server does not exist") from error
        store = VirtualminBackupService(target)
        recovery = VirtualminRecoveryService()
        plans = []
        for account in source.accounts.filter(status__in=("active", "suspended")).order_by("pk"):
            inventory = store.list_backups(account=account)
            if inventory.is_err():
                raise CommandError(f"{account.domain}: {inventory.unwrap_err()}")
            selected = select_recovery_backups(account, inventory.unwrap())
            if selected.is_err():
                raise CommandError(f"{account.domain}: {selected.unwrap_err()}")
            plans.append((account, selected.unwrap()))
        for account, backup_ids in plans:
            self.stdout.write(f"{account.domain} -> {target.hostname}: {', '.join(backup_ids)} ({account.status})")
        if not options["apply"]:
            self.stdout.write(f"Dry run: {len(plans)} account(s); no node changes or recovery jobs issued.")
            return
        for account, backup_ids in plans:
            result = recovery.start_recovery(
                account, target, backup_ids=backup_ids, source_fenced=options["source_fenced"]
            )
            if result.is_err():
                raise CommandError(
                    f"{account.domain}: {result.unwrap_err()}; earlier listed jobs may already be queued"
                )
            self.stdout.write(self.style.SUCCESS(f"Queued recovery {result.unwrap().pk} for {account.domain}"))
