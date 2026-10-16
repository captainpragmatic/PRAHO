"""Read-only readiness checks for the stored selling currency, its FX evidence and the home currency.

Database access is explicit: use ``check --tag billing_currency --database default`` (``migrate``
runs them for its database). Ordinary checks and imports stay offline. A missing pre-upgrade schema
keeps the bootstrap baseline, allowing migrations to install the policy safely.
"""

from __future__ import annotations

from collections.abc import Sequence

from django.core.checks import Error, Tags, register
from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError, InterfaceError, connections, router
from django.utils import timezone


def _column_installed(alias: str, table: str, column_name: str) -> bool:
    connection = connections[alias]
    with connection.cursor() as cursor:
        if table not in connection.introspection.table_names(cursor):
            return False
        columns = connection.introspection.get_table_description(cursor, table)
    return any(column.name == column_name for column in columns)


@register("billing_currency", Tags.database)
def check_billing_default_currency(*, databases: Sequence[str] | None = None, **_kwargs: object) -> list[Error]:
    """Validate the installed policy only when its database was explicitly selected."""
    from apps.billing.currency_policy import get_selling_currency_policy  # noqa: PLC0415
    from apps.billing.currency_service import (  # noqa: PLC0415  # ADR-0007: deferred billing dependency
        CurrencyNotIssuableError,
        CurrencyValidationError,
        assert_currency_issuable,
    )
    from apps.settings.models import SystemSetting  # noqa: PLC0415  # ADR-0007: deferred settings dependency

    alias = router.db_for_read(SystemSetting)
    if not databases or alias not in databases:
        return []

    try:
        if not _column_installed(alias, SystemSetting._meta.db_table, "revision"):
            return []
        policy = get_selling_currency_policy()
        assert_currency_issuable(policy.currency_code, timezone.localdate())
    except (CurrencyValidationError, CurrencyNotIssuableError) as exc:
        return [
            Error(
                f"billing.default_currency: {exc}",
                hint="Correct the stored selling policy or provision a provenanced rate effective today or earlier.",
                id="billing.E001",
            )
        ]
    except (AttributeError, TypeError):
        return [Error("billing.default_currency must be a supported currency-code string.", id="billing.E001")]
    except (DatabaseError, InterfaceError):
        return [
            Error(
                "billing.default_currency could not be validated against the policy and FX-rate database.",
                hint="Restore database access and apply pending migrations, then rerun the currency readiness check.",
                obj=alias,
                id="billing.E002",
            )
        ]

    return []


@register("billing_currency", Tags.database)
def check_home_currency_matches_issued_invoices(
    *, databases: Sequence[str] | None = None, **_kwargs: object
) -> list[Error]:
    """Issued invoices froze their rates into one home currency, which follows COMPANY_COUNTRY_CODE.

    Changing the operator's country under them would reinterpret every frozen rate, so it is refused.
    """
    from apps.billing.currency_service import home_currency  # noqa: PLC0415  # ADR-0007
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415  # ADR-0007

    alias = router.db_for_read(Invoice)
    if not databases or alias not in databases:
        return []
    try:
        if not _column_installed(alias, Invoice._meta.db_table, "home_currency_code"):
            return []
        home = home_currency()
        recorded = sorted(
            code
            for code in Invoice.objects.using(alias)
            .filter(home_currency_code__isnull=False)
            .exclude(home_currency_code__in=(home, ""))
            .values_list("home_currency_code", flat=True)
            .distinct()
            if code
        )
    except ImproperlyConfigured:
        return []  # An operator outside the EU has no home currency; common.E003 reports it.
    except (DatabaseError, InterfaceError):
        return []  # billing.E002 reports an unreachable database.
    if not recorded:
        return []
    return [
        Error(
            f"Issued invoices record the home currency {', '.join(recorded)}, but COMPANY_COUNTRY_CODE now gives {home}.",
            hint="An operator's accounting currency cannot change under issued invoices. Restore COMPANY_COUNTRY_CODE.",
            id="billing.E003",
        )
    ]
