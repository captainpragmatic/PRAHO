"""Read-only readiness checks for the stored selling currency and its FX evidence.

Database access is explicit: use ``check --tag billing_currency --database default``.
Ordinary checks and imports stay offline. Missing pre-upgrade settings schema keeps
the RON bootstrap baseline, allowing migrations to install the policy safely.
"""

from __future__ import annotations

from collections.abc import Sequence

from django.core.checks import Error, Tags, register
from django.db import DatabaseError, connections, router
from django.utils import timezone


def _policy_schema_installed(alias: str, table: str) -> bool:
    connection = connections[alias]
    with connection.cursor() as cursor:
        if table not in connection.introspection.table_names(cursor):
            return False
        columns = connection.introspection.get_table_description(cursor, table)
    return any(column.name == "revision" for column in columns)


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
        if not _policy_schema_installed(alias, SystemSetting._meta.db_table):
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
    except DatabaseError:
        return [
            Error(
                "billing.default_currency could not be validated against the policy and FX-rate database.",
                hint="Restore database access and apply pending migrations, then rerun the currency readiness check.",
                obj=alias,
                id="billing.E002",
            )
        ]

    return []
