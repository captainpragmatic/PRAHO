"""Snapshot the charged campaign on CouponRedemption (#481).

mark_reversed() used to decrement the coupon's CURRENT campaign, which is
admin-editable: a redemption applied under campaign A could be reversed against
campaign B, leaving A charged forever and driving B's spent_cents silently
negative (no >= 0 database constraint exists on it). The snapshot recorded at
application time becomes the authoritative reversal target.

The backfill sets charged_campaign_id = coupon.campaign_id for rows still in
status="applied" — the coupon's campaign AT MIGRATION TIME, which is exactly
what the pre-#481 code would have decremented had the reversal run at this
moment. This is an approximation with known, unrecoverable failure modes for
rows whose coupon's campaign was reassigned between application and this
migration (the original campaign was never recorded anywhere):

- coupon had NO campaign when applied, later assigned to B → snapshot says B
  (never charged); a future reversal decrements B — identical to the pre-#481
  behavior at this moment, no worse, now frozen instead of drifting further.
- coupon charged A, later moved to B → snapshot says B; reversal leaves A
  charged and decrements B — again identical to pre-#481 behavior today.
- coupon charged A, campaign later cleared → snapshot stays NULL; reversal
  restores nothing — pre-#481 behavior was the same (current campaign None).

The alternative — leaving every historical row NULL — would be strictly safer
for the (rare, unmeasurable) reassigned rows but strictly worse for the common
never-reassigned case, where it would permanently stop budget restoration for
every cancellation of a pre-migration order. Rolling-deploy note: an old worker
still running pre-#481 code can create applied rows AFTER this backfill runs;
those rows carry a NULL snapshot and reverse without a campaign decrement — a
deploy-window-sized gap that closes with the deploy itself.

Terminal rows (reversed/failed/expired/pending) are left NULL: they will never
be reversed. Reverse migration is a no-op beyond dropping the column.
"""

from __future__ import annotations

from django.db import migrations, models
from django.db.models import OuterRef, Subquery


def backfill_charged_campaign(apps, _schema_editor) -> None:
    coupon = apps.get_model("promotions", "Coupon")
    coupon_redemption = apps.get_model("promotions", "CouponRedemption")

    # One set-based statement instead of a Python loop of per-row UPDATEs —
    # the redemption table is the highest-volume table in this app.
    coupon_redemption.objects.filter(status="applied", charged_campaign_id__isnull=True).update(
        charged_campaign_id=Subquery(coupon.objects.filter(pk=OuterRef("coupon_id")).values("campaign_id")[:1])
    )


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
