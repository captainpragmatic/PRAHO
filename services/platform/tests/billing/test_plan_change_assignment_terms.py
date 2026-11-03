"""A settled commercial claim applies its frozen allowance rather than a later catalog edit."""

from dataclasses import replace
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import TestCase

from apps.provisioning.hosting_limit_assignments import assignment_terms_for_plan, request_service_plan_change
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_policy import HostingAssignmentTerms
from apps.provisioning.models import ServicePlan
from tests.billing.test_plan_change_models import _PlanChangeFixture


class AcceptedAssignmentTermsTests(_PlanChangeFixture, TestCase):
    def test_catalog_edit_after_claim_cannot_reprice_resource_coverage(self) -> None:
        plan = ServicePlan.objects.create(
            name="Accepted", plan_type="shared_hosting", price_monthly=200, disk_space_gb=20, bandwidth_gb=100
        )
        accepted = assignment_terms_for_plan(plan)
        snapshot = accepted.as_snapshot()
        plan.disk_space_gb, plan.bandwidth_gb = 30, 150
        plan.save(update_fields=["disk_space_gb", "bandwidth_gb"])
        arguments = {
            "service": self.service,
            "target_plan_id": plan.pk,
            "expected_revision": 1,
            "submission_id": uuid4(),
            "reason": "Paid accepted quote",
            "authority": {"kind": "paid_plan_change"},
            "accepted_terms": HostingAssignmentTerms.from_snapshot(snapshot),
        }
        with transaction.atomic():
            application = request_service_plan_change(**arguments)
        current = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual((current.disk_allowance_mib, current.bandwidth_allowance_mib), (20480, 102400))
        self.assertEqual(application.disk_allowance_mib, 20480)
        with transaction.atomic():
            replay = request_service_plan_change(**arguments)
        self.assertEqual(replay.pk, application.pk)
        arguments["accepted_terms"] = replace(accepted, disk_allowance_mib=21000)
        with transaction.atomic(), self.assertRaises(ValidationError):
            request_service_plan_change(**arguments)

    def test_accepted_terms_refuse_retargeting_and_changed_idempotent_replay(self) -> None:
        accepted = assignment_terms_for_plan(self.plan)
        other = ServicePlan.objects.create(name="Other", plan_type="shared_hosting", price_monthly=200)
        with transaction.atomic(), self.assertRaises(ValueError):
            request_service_plan_change(
                service=self.service,
                target_plan_id=other.pk,
                expected_revision=1,
                submission_id=uuid4(),
                reason="Wrong resource target",
                authority={"kind": "paid_plan_change"},
                accepted_terms=accepted,
            )

    def test_snapshot_rejects_bool_unknown_extra_fields_and_policy_changes(self) -> None:
        snapshot = assignment_terms_for_plan(self.plan).as_snapshot()
        for update in (
            {"disk_allowance_mib": True},
            {"bandwidth_allowance_mib": None},
            {"policy_version": 2},
            {"hidden_extra": 1},
            {"disk_source": "legacy_unknown"},
        ):
            with self.subTest(update=update), self.assertRaises(ValueError):
                HostingAssignmentTerms.from_snapshot({**snapshot, **update})
