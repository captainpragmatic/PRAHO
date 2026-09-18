"""
Seed the audit retention policies (ADR-0043).

Without seeded policies the retention engine has nothing to apply and audit data
grows forever - which is itself a GDPR Article 5(1)(e) storage-limitation problem.

Conflict policy: exactly one active policy per (category, severity) slot (DB
constraint). Existing conflicting rows are reported and the command refuses to
proceed unless --repair deactivates them (mandatory rows are never auto-repaired).
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.audit.models import AuditRetentionPolicy, audit_mutation_allowed
from apps.common.operator import operator_country

# One entry per category slot (severity="" means the whole category).
#
# A "jurisdiction" key marks a period derived from one country's national law.
# Those install as mandatory only where the operator is actually established —
# the action EXECUTES, and a mandatory row is harder to back out than to add.
# Entries without the key rest on EU-wide obligations and seed everywhere.
RETENTION_POLICY_SEED: tuple[dict[str, Any], ...] = (
    {
        "name": "Business operations - Romanian accounting retention",
        "category": "business_operation",
        "severity": "",
        "jurisdiction": "RO",
        "retention_days": 3653,  # 10 years, Legea contabilitatii
        "action": "delete",
        "legal_basis": "Legea contabilitatii nr. 82/1991 (10-year financial records)",
        "is_mandatory": True,
    },
    {
        "name": "Authentication events - 2 year anonymization",
        "category": "authentication",
        "severity": "",
        "retention_days": 731,
        "action": "anonymize",
        "legal_basis": "GDPR Art. 5(1)(e) storage limitation",
        "is_mandatory": False,
    },
    {
        "name": "Security events - 2 year anonymization",
        "category": "security_event",
        "severity": "",
        "retention_days": 731,
        "action": "anonymize",
        "legal_basis": "GDPR Art. 5(1)(e) storage limitation",
        "is_mandatory": False,
    },
    {
        "name": "Privacy events - GDPR accountability retention",
        "category": "privacy",
        "severity": "",
        "retention_days": 1827,  # 5 years
        "action": "anonymize",
        "legal_basis": (
            "GDPR Art. 5(1)(e) storage limitation with Art. 5(2) accountability "
            "(operator-configurable reference period, not a prescribed statutory term)"
        ),
        "is_mandatory": True,
    },
    {
        "name": "Data protection events - GDPR accountability retention",
        "category": "data_protection",
        "severity": "",
        "retention_days": 1827,
        "action": "anonymize",
        "legal_basis": (
            "GDPR Art. 5(1)(e) storage limitation with Art. 5(2) accountability "
            "(operator-configurable reference period, not a prescribed statutory term)"
        ),
        "is_mandatory": True,
    },
    {
        "name": "Authorization events - 3 year deletion",
        "category": "authorization",
        "severity": "",
        "retention_days": 1096,
        "action": "delete",
        "legal_basis": "GDPR Art. 5(1)(e) storage limitation",
        "is_mandatory": False,
    },
    {
        "name": "Account management events - 3 year deletion",
        "category": "account_management",
        "severity": "",
        "retention_days": 1096,
        "action": "delete",
        "legal_basis": "GDPR Art. 5(1)(e) storage limitation",
        "is_mandatory": False,
    },
    {
        "name": "System administration events - 3 year deletion",
        "category": "system_admin",
        "severity": "",
        "retention_days": 1096,
        "action": "delete",
        "legal_basis": "GDPR Art. 5(1)(e) storage limitation",
        "is_mandatory": False,
    },
    {
        "name": "Compliance events - 3 year deletion",
        "category": "compliance",
        "severity": "",
        "retention_days": 1096,
        "action": "delete",
        "legal_basis": "GDPR Art. 5(1)(e) storage limitation",
        "is_mandatory": False,
    },
    {
        "name": "Integration events - 3 year deletion",
        "category": "integration",
        "severity": "",
        "retention_days": 1096,
        "action": "delete",
        "legal_basis": "GDPR Art. 5(1)(e) storage limitation",
        "is_mandatory": False,
    },
)


class Command(BaseCommand):
    help = "Seed audit retention policies (idempotent; --repair deactivates conflicting non-mandatory rows)"

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--repair",
            action="store_true",
            help="Deactivate non-mandatory policies that conflict with the seed set",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Install jurisdiction-specific mandatory policies even when the operator jurisdiction differs",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        created = updated = skipped = 0
        established_in = operator_country()
        force = bool(options.get("force", False))

        with transaction.atomic():
            for spec in RETENTION_POLICY_SEED:
                jurisdiction = spec.get("jurisdiction")
                if jurisdiction and spec["is_mandatory"] and jurisdiction != established_in and not force:
                    raise CommandError(
                        f"Refusing to seed {spec['name']!r}: it derives from {jurisdiction} national law "
                        f"but this deployment is established in {established_in}. The policy is mandatory "
                        "and its action executes. Set COMPANY_COUNTRY_CODE, or pass --force to install it."
                    )

                # The model has no jurisdiction field - it is seed metadata only.
                model_spec = {key: value for key, value in spec.items() if key != "jurisdiction"}
                conflict = (
                    AuditRetentionPolicy.objects.filter(
                        category=spec["category"], severity=spec["severity"], is_active=True
                    )
                    .exclude(name=spec["name"])
                    .first()
                )
                if conflict is not None:
                    if not options["repair"]:
                        raise CommandError(
                            f"Active policy '{conflict.name}' already claims "
                            f"({spec['category']}, {spec['severity'] or '*'}) - "
                            "re-run with --repair to deactivate it, or resolve manually"
                        )
                    if conflict.is_mandatory:
                        raise CommandError(
                            f"Refusing to auto-repair mandatory policy '{conflict.name}' - "
                            "a legal retention rule needs a human decision"
                        )
                    conflict.is_active = False
                    conflict.save(update_fields=["is_active", "updated_at"])
                    self.stdout.write(self.style.WARNING(f"  deactivated conflicting policy: {conflict.name}"))

                existing = AuditRetentionPolicy.objects.filter(name=spec["name"]).first()
                if existing is None:
                    AuditRetentionPolicy.objects.create(**model_spec, is_active=True)
                    created += 1
                    self.stdout.write(self.style.SUCCESS(f"  created: {spec['name']}"))
                elif (
                    existing.retention_days != spec["retention_days"]
                    or existing.action != spec["action"]
                    or existing.is_mandatory != spec["is_mandatory"]
                    or existing.legal_basis != spec["legal_basis"]
                    or not existing.is_active
                ):
                    # Reconciling a drifted seed row may touch mandatory flags - that is
                    # exactly what the escape hatch exists to make explicit.
                    with audit_mutation_allowed("retention_policy_seed"):
                        for field_name in ("retention_days", "action", "legal_basis", "is_mandatory"):
                            setattr(existing, field_name, model_spec[field_name])
                        existing.is_active = True
                        existing.save()
                    updated += 1
                    self.stdout.write(self.style.WARNING(f"  reconciled: {spec['name']}"))
                else:
                    skipped += 1

        self.stdout.write(
            self.style.SUCCESS(f"Retention policies: {created} created, {updated} reconciled, {skipped} unchanged")
        )
