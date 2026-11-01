"""Owned noncredential fixtures for the real Platform/Portal maintenance acceptance run."""

from __future__ import annotations

import json
import os
import secrets
from decimal import Decimal
from pathlib import Path
from typing import TypedDict, cast
from uuid import UUID


class FixtureScope(TypedDict):
    node_ids: list[str]
    customer_ids: list[int]
    service_ids: list[int]
    window_ids: list[str]


class FixtureLogin(TypedDict):
    email: str
    password: str


class FixtureManifest(TypedDict):
    staff: FixtureLogin
    viewer: FixtureLogin
    scope: FixtureScope
    customers: list[int]
    services: list[int]
    protected_queue_ids: list[int]
    unrelated_email_log_id: str


def read_manifest() -> FixtureManifest:
    return cast("FixtureManifest", json.loads(Path(os.environ["VIRTUALMIN_MAINTENANCE_MANIFEST"]).read_text()))


def write_manifest(data: FixtureManifest) -> None:
    path = Path(os.environ["VIRTUALMIN_MAINTENANCE_MANIFEST"])
    temporary = path.with_suffix(".new")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(data, output)
    temporary.chmod(0o600)
    temporary.replace(path)


def own_window(window_id: UUID | str) -> None:
    from apps.infrastructure.node_maintenance_models import (  # noqa: PLC0415 -- Platform fixture only, after Django setup
        NodeMaintenanceWindow,
    )

    manifest = read_manifest()
    window = NodeMaintenanceWindow.objects.get(pk=window_id)
    assert str(window.node_id) in manifest["scope"]["node_ids"], "Refusing a foreign window"
    manifest["scope"]["window_ids"] = sorted({*manifest["scope"]["window_ids"], str(window.pk)})
    write_manifest(manifest)


def seed() -> None:
    """Only a newly migrated, owned seed DB; never invokes the native lab bootstrap."""
    from django.conf import settings  # noqa: PLC0415
    from django.utils import timezone  # noqa: PLC0415
    from django_q.models import OrmQ  # noqa: PLC0415
    from django_q.signing import SignedPackage  # noqa: PLC0415

    from apps.billing.currency_models import Currency  # noqa: PLC0415
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.notifications.models import EmailLog, EmailTemplate  # noqa: PLC0415
    from apps.provisioning.service_models import Service, ServicePlan  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer  # noqa: PLC0415
    from apps.users.models import CustomerMembership, User, UserProfile  # noqa: PLC0415

    assert settings.VIRTUALMIN_MAINTENANCE_LAB is True
    assert Path(settings.DATABASES["default"]["NAME"]).name == "seed.sqlite3"
    assert not User.objects.exists(), "Acceptance seeding refuses a populated database"
    assert (
        EmailTemplate.objects.filter(
            key__in=("maintenance_scheduled", "maintenance_completed", "maintenance_correction"),
            locale__in=("en", "ro"),
        ).count()
        == 6
    ), "Run the production maintenance template migration first"
    password = secrets.token_urlsafe(24)
    staff = User.objects.create_superuser(email="maintenance-staff@praho.test", password=password)
    viewer = User.objects.create_user(
        email="maintenance-customer@praho.test",
        password=password,
        first_name="Maintenance",
        last_name="Customer",
        phone="+40721123456",
        last_privacy_policy_accepted=timezone.now(),
        terms_accepted_at=timezone.now(),
    )
    for user in (staff, viewer):
        UserProfile.objects.update_or_create(user=user, defaults={"preferred_language": "en", "timezone": "UTC"})
    customers = [
        Customer.objects.create(
            name=f"Maintenance acceptance {label}", primary_email=f"maintenance-{label.lower()}@praho.test"
        )
        for label in ("A", "B", "Outside")
    ]
    for index, customer in enumerate(customers[:2]):
        CustomerMembership.objects.create(
            customer=customer,
            user=viewer,
            role="owner",
            is_primary=index == 0,
            notification_language="en",
        )
    Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
    plan = ServicePlan.objects.create(name="Maintenance acceptance hosting", price_monthly=Decimal("10.00"))
    nodes = [
        VirtualminServer.objects.create(
            name=f"Maintenance acceptance node {label}",
            hostname=f"maintenance-{label}.lab.invalid",
            api_username="",
            status="active",
        )
        for label in ("a", "b")
    ]
    services = []
    for index, customer in enumerate([*customers, customers[0]]):
        domain = f"maintenance-{index}.example.test"
        service = Service.objects.create(
            customer=customer,
            service_plan=plan,
            currency_id="RON",
            service_name=f"Maintenance hosting {index}",
            domain=domain,
            username=f"maintenance{index}",
            price=Decimal("10.00"),
            status="active",
        )
        VirtualminAccount.objects.create(
            service=service,
            server=nodes[1] if index == 3 else nodes[0],
            domain=domain,
            virtualmin_username=service.username,
            status="active",
        )
        services.append(service)
    unrelated_log = EmailLog.objects.create(
        to_addr="unrelated-mail@praho.test",
        subject="Unrelated fixture work",
        body_text="Keep queued",
    )
    protected = []
    for func, args in (
        ("apps.infrastructure.tasks.reboot_node_task", (-1,)),
        ("apps.notifications.tasks.send_email_task", (str(unrelated_log.pk),)),
        ("apps.infrastructure.node_maintenance_tasks.tick_node_maintenance", ()),
    ):
        row = OrmQ.objects.create(
            key="maintenance-lab",
            payload=SignedPackage.dumps({"id": secrets.token_hex(16), "func": func, "args": args, "kwargs": {}}),
        )
        protected.append(row.pk)
    write_manifest(
        {
            "staff": {"email": staff.email, "password": password},
            "viewer": {"email": viewer.email, "password": password},
            "scope": {
                "node_ids": [str(node.pk) for node in nodes],
                "customer_ids": [customer.pk for customer in customers],
                "service_ids": [service.pk for service in services],
                "window_ids": [],
            },
            "customers": [customer.pk for customer in customers],
            "services": [service.pk for service in services],
            "protected_queue_ids": protected,
            "unrelated_email_log_id": str(unrelated_log.pk),
        }
    )
