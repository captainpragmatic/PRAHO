"""Snapshot the charged campaign on CouponRedemption (#481).

mark_reversed() used to decrement the coupon's CURRENT campaign, which is
admin-editable: a redemption applied under campaign A could be reversed against
campaign B, leaving A charged forever and driving B's spent_cents silently
negative (no >= 0 database constraint exists on it). The snapshot recorded at
application time becomes the authoritative reversal target.

The backfill sets charged_campaign_id = coupon.campaign_id for rows still in
status="applied" — the best available approximation at migration time, exactly
equivalent to the pre-#481 reversal behavior at this moment, and strictly
better than a runtime fallback that would keep drifting with future
reassignments. Drift that already happened before this migration (a coupon
reassigned while redemptions were applied) is unrecoverable — the original
campaign was never recorded anywhere. Terminal rows (reversed/failed/expired)
are left NULL: they will never be reversed.

Reverse is a no-op beyond dropping the column: no data change is needed to run
the pre-#481 code, which ignores the snapshot entirely.
"""

from __future__ import annotations

from django.db import migrations, models


def backfill_charged_campaign(apps, _schema_editor) -> None:
    coupon_redemption = apps.get_model("promotions", "CouponRedemption")
    coupon = apps.get_model("promotions", "Coupon")

    campaign_by_coupon = dict(coupon.objects.exclude(campaign__isnull=True).values_list("pk", "campaign_id"))
    to_fix = coupon_redemption.objects.filter(status="applied", charged_campaign_id__isnull=True)
    for redemption in to_fix.iterator():
        campaign_id = campaign_by_coupon.get(redemption.coupon_id)
        if campaign_id is not None:
            coupon_redemption.objects.filter(pk=redemption.pk).update(charged_campaign_id=campaign_id)


class Migration(migrations.Migration):
    dependencies = [
        ("promotions", "0002_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="couponredemption",
            name="charged_campaign_id",
            field=models.UUIDField(
                blank=True,
                editable=False,
                help_text="Campaign whose budget was charged when this redemption was applied",
                null=True,
            ),
        ),
        migrations.RunPython(backfill_charged_campaign, migrations.RunPython.noop),
    ]
