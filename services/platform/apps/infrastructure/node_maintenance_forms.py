"""Operator-input forms; timezone interpretation belongs to the explicit node policy."""

from collections.abc import Mapping
from typing import TYPE_CHECKING, ClassVar

from django import forms
from django.utils.functional import Promise
from django.utils.translation import gettext_lazy as _

from apps.infrastructure.node_maintenance_gate import ACTIVE_EXECUTIONS
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceExecution,
    NodeMaintenancePolicy,
    NodeMaintenanceWindow,
)

_WEEKDAY_LABELS = (_("Monday"), _("Tuesday"), _("Wednesday"), _("Thursday"), _("Friday"), _("Saturday"), _("Sunday"))

if TYPE_CHECKING:
    _PolicyFormBase = forms.ModelForm[NodeMaintenancePolicy]
else:
    _PolicyFormBase = forms.ModelForm


class NodeMaintenancePolicyForm(_PolicyFormBase):
    revision = forms.IntegerField(required=False, min_value=0, widget=forms.HiddenInput)
    weekdays = forms.TypedMultipleChoiceField(
        label=_("Permitted weekdays"),
        choices=tuple(enumerate(_WEEKDAY_LABELS)),
        coerce=int,
        widget=forms.CheckboxSelectMultiple,
    )

    @property
    def weekday_options(self) -> list[dict[str, object]]:
        selected = {str(value) for value in self["weekdays"].value() or []}
        return [
            {"value": str(value), "label": label, "selected": str(value) in selected, "id": f"policy-weekday-{value}"}
            for value, label in enumerate(_WEEKDAY_LABELS)
        ]

    class Meta:
        model = NodeMaintenancePolicy
        fields = ("timezone", "weekdays", "starts_time", "ends_time", "max_defer_minutes")
        widgets: ClassVar[dict[str, forms.Widget]] = {
            "starts_time": forms.TimeInput(attrs={"type": "time"}),
            "ends_time": forms.TimeInput(attrs={"type": "time"}),
            "max_defer_minutes": forms.NumberInput(attrs={"min": 0, "max": 1440}),
        }
        labels: ClassVar[dict[str, str | Promise]] = {
            "timezone": _("Permitted scheduling timezone"),
            "weekdays": _("Permitted weekdays"),
            "starts_time": _("Permitted interval start"),
            "ends_time": _("Permitted interval end"),
            "max_defer_minutes": _("Latest-start deferral (minutes)"),
        }
        help_texts: ClassVar[dict[str, str | Promise]] = {
            "timezone": _("Use an IANA timezone, for example Europe/Bucharest. No fleet-wide default is assumed."),
            "max_defer_minutes": _(
                "New policies suggest 15 minutes; review and save the permitted delay. Zero permits no late start; delayed work is recorded as not run."
            ),
        }


class NodeMaintenanceWindowForm(forms.Form):
    policy_revision = forms.IntegerField(required=False, min_value=1, widget=forms.HiddenInput)
    kind = forms.ChoiceField(
        label=_("Maintenance kind"),
        choices=(("panel_update", _("Hosting software updates")), ("reboot", _("Restart"))),
    )
    execution_mode = forms.ChoiceField(
        label=_("Execution mode"),
        choices=(
            ("manual", _("Operator managed")),
            ("reboot", _("Provider restart")),
        ),
    )
    starts_at = forms.CharField(label=_("Planned start (policy timezone or explicit UTC offset)"))
    ends_at = forms.CharField(label=_("Planned end (policy timezone or explicit UTC offset)"))
    expects_downtime = forms.BooleanField(required=False, label=_("Downtime is expected"))
    expected_downtime_minutes = forms.IntegerField(
        min_value=0, required=False, label=_("Expected unavailability (minutes)")
    )
    customer_note = forms.CharField(
        max_length=1000, widget=forms.Textarea(attrs={"rows": 3}), label=_("Customer impact note")
    )

    def clean(self) -> dict[str, object]:
        values = super().clean() or {}
        kind, mode = values.get("kind"), values.get("execution_mode")
        permitted = {"reboot": {"manual", "reboot"}, "panel_update": {"manual"}}
        if isinstance(kind, str) and kind in permitted and mode not in permitted[kind]:
            self.add_error("execution_mode", _("Choose an execution mode that matches the announced maintenance kind."))
        if mode == "reboot" and not values.get("expects_downtime"):
            self.add_error(
                "expects_downtime",
                _("A provider restart interrupts availability; its notice must declare expected downtime."),
            )
        return values


class NodeMaintenanceActionForm(forms.Form):
    revision = forms.IntegerField(min_value=1, widget=forms.HiddenInput)
    reason = forms.CharField(max_length=2000, widget=forms.Textarea(attrs={"rows": 3}), label=_("Decision reason"))
    confirmation = forms.BooleanField(label=_("I have reviewed the maintenance impact and approve this decision."))
    attestation = forms.BooleanField(
        label=_("I confirm remote commands have stopped and the stated readiness has been checked.")
    )
    outcome = forms.ChoiceField(
        choices=(("completed", _("Completed")), ("failed", _("Failed"))), label=_("Actual outcome")
    )
    public_outcome = forms.CharField(
        max_length=2000, widget=forms.Textarea(attrs={"rows": 3}), label=_("Outcome for affected customers")
    )
    starts_at = forms.CharField(label=_("Replacement start (policy timezone or explicit UTC offset)"))
    ends_at = forms.CharField(label=_("Replacement end (policy timezone or explicit UTC offset)"))
    customer_note = forms.CharField(
        required=False,
        max_length=1000,
        widget=forms.Textarea(attrs={"rows": 3}),
        label=_("Updated customer impact note (optional)"),
    )


def maintenance_action_form(
    window: NodeMaintenanceWindow, action: str, data: Mapping[str, object] | None = None
) -> NodeMaintenanceActionForm:
    form = NodeMaintenanceActionForm(
        data=data,
        initial={
            "revision": window.revision,
            "starts_at": window.starts_at.isoformat(),
            "ends_at": window.ends_at.isoformat(),
        },
        auto_id=f"maintenance-{window.pk}-{action}-%s",
    )
    wanted = {"revision", "reason", "confirmation"}
    if action == "finish":
        wanted |= {"attestation", "outcome", "public_outcome"}
    elif action == "move":
        wanted |= {"starts_at", "ends_at", "customer_note"}
    for name in tuple(form.fields):
        if name not in wanted:
            del form.fields[name]
    form.fields["confirmation"].label = {
        "start": _("I reviewed affected services and active operations and approve starting this maintenance."),
        "finish": _("I reviewed the checked outcome and approve its customer-facing completion report."),
        "move": _(
            "I understand the replacement schedule supersedes the earlier revision and creates correction notices for customers already notified, subject to their preferences."
        ),
        "cancel": _(
            "I understand cancellation withdraws unstarted work and creates correction notices for customers already notified, subject to their preferences."
        ),
    }[action]
    return form


class NodeMaintenanceReconcileForm(forms.Form):
    expected_phase = forms.ChoiceField(
        choices=tuple((phase, phase) for phase in ACTIVE_EXECUTIONS), widget=forms.HiddenInput
    )
    outcome = forms.ChoiceField(
        choices=(("verified", _("Verified outcome")), ("failed", _("Failed outcome"))), label=_("Actual outcome")
    )
    reason = forms.CharField(max_length=2000, widget=forms.Textarea(attrs={"rows": 3}), label=_("Decision reason"))
    commands_stopped = forms.BooleanField(label=_("I confirm no commands for this recorded operation remain running."))
    resource_confirmed = forms.BooleanField(
        label=_("I checked the actual target against the recorded resource identity shown above.")
    )


def maintenance_reconcile_form(
    execution: NodeMaintenanceExecution, data: Mapping[str, object] | None = None
) -> NodeMaintenanceReconcileForm:
    form = NodeMaintenanceReconcileForm(
        data=data, initial={"expected_phase": execution.phase}, auto_id=f"direct-operation-{execution.pk}-%s"
    )
    if execution.phase == "claimed":
        form.fields["outcome"] = forms.ChoiceField(
            choices=(("failed", _("Not run (no command issued)")),), label=_("Actual outcome")
        )
    return form
