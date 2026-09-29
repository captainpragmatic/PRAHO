"""Staff promotion workflows must render and persist through their real views."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.promotions.forms import CouponForm, PromotionRuleForm
from apps.promotions.models import Coupon, GiftCard, PromotionCampaign, PromotionRule


class PromotionStaffWorkflowTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.staff = get_user_model().objects.create_user(
            email="promotions-staff@example.test", password="SecurePass123!", staff_role="admin", is_staff=True
        )
        cls.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"})
        cls.campaign = PromotionCampaign.objects.create(
            name="Spring Campaign", slug="spring-campaign", start_date=timezone.now()
        )
        cls.coupon = Coupon.objects.create(
            code="SPRING10", name="Spring coupon", discount_type="percent", discount_percent=10
        )
        cls.gift = GiftCard.objects.create(
            code="STAFF-GIFT", initial_value_cents=1000, current_balance_cents=0, currency=cls.currency
        )
        cls.rule = PromotionRule.objects.create(name="Spring rule", discount_type="percent", discount_percent=5)

    def setUp(self) -> None:
        self.client.force_login(self.staff)

    def test_all_staff_routes_render_real_controls_or_records(self) -> None:
        routes = {
            "dashboard": (None, "Promotions"),
            "campaign_list": (None, "Spring Campaign"),
            "campaign_create": (None, 'name="name"'),
            "campaign_detail": (self.campaign.pk, "Spring Campaign"),
            "campaign_update": (self.campaign.pk, 'name="name"'),
            "coupon_list": (None, "SPRING10"),
            "coupon_create": (None, 'name="discount_type"'),
            "coupon_batch_create": (None, 'name="count"'),
            "coupon_detail": (self.coupon.pk, "SPRING10"),
            "coupon_update": (self.coupon.pk, 'name="discount_type"'),
            "gift_card_list": (None, self.gift.masked_code),
            "gift_card_create": (None, 'name="initial_value_cents"'),
            "gift_card_detail": (self.gift.pk, self.gift.masked_code),
            "referral_list": (None, "Referrals"),
            "loyalty_dashboard": (None, "Loyalty"),
            "rule_list": (None, "Spring rule"),
            "rule_create": (None, 'name="minimum_subtotal"'),
            "rule_update": (self.rule.pk, 'name="minimum_subtotal"'),
        }
        for name, (pk, text) in routes.items():
            with self.subTest(route=name):
                response = self.client.get(reverse(f"promotions:{name}", kwargs={"pk": pk} if pk else None))
                self.assertContains(response, text)

    def test_campaign_edit_uses_a_valid_transition_and_persists(self) -> None:
        response = self.client.post(
            reverse("promotions:campaign_update", kwargs={"pk": self.campaign.pk}),
            {
                "name": "Edited campaign",
                "slug": self.campaign.slug,
                "campaign_type": "other",
                "start_date": self.campaign.start_date.isoformat(),
                "status": "active",
                "is_active": "on",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.name, "Edited campaign")
        self.assertEqual(self.campaign.status, "active")

    def test_invalid_batch_keeps_input_and_creates_no_coupons(self) -> None:
        before = Coupon.objects.count()
        response = self.client.post(
            reverse("promotions:coupon_batch_create"),
            {
                "count": "2",
                "prefix": "TEST",
                "name": "Bad batch",
                "discount_type": "percent",
                "discount_percent": "101",
                "discount_amount_cents": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Bad batch")
        self.assertTrue(response.context["form"].errors)
        self.assertEqual(Coupon.objects.count(), before)

    def test_batch_saves_normalized_codes_and_actor_audit(self) -> None:
        response = self.client.post(
            reverse("promotions:coupon_batch_create"),
            {
                "count": "2",
                "prefix": "qa",
                "name": "Audited batch",
                "discount_type": "percent",
                "discount_percent": "10",
                "discount_amount_cents": "",
                "currency": self.currency.pk,
            },
        )
        self.assertEqual(response.status_code, 302)
        coupons = list(Coupon.objects.filter(name="Audited batch"))
        self.assertEqual(len(coupons), 2)
        self.assertTrue(all(coupon.code.startswith("QA") for coupon in coupons))
        self.assertTrue(all(coupon.created_by_id == self.staff.pk for coupon in coupons))
        self.assertTrue(AuditEvent.objects.filter(user=self.staff, action="coupon_batch_created").exists())

    def test_customer_cannot_read_or_write_staff_promotions(self) -> None:
        user = get_user_model().objects.create_user(email="promo-customer@example.test", password="SecurePass123!")
        self.client.force_login(user)
        self.assertEqual(self.client.get(reverse("promotions:dashboard")).status_code, 403)
        self.assertEqual(self.client.post(reverse("promotions:coupon_batch_create"), {"count": 2}).status_code, 403)

    def test_support_can_read_offers_without_an_unusable_edit_link(self) -> None:
        support = get_user_model().objects.create_user(email="promo-support@example.test", staff_role="support")
        self.client.force_login(support)
        edit_url = reverse("promotions:rule_update", kwargs={"pk": self.rule.pk})
        response = self.client.get(reverse("promotions:rule_list"))
        self.assertContains(response, self.rule.name)
        self.assertNotContains(response, edit_url)
        self.assertEqual(self.client.get(edit_url).status_code, 403)
        self.assertEqual(self.client.post(edit_url, {"name": "Forbidden change"}).status_code, 403)
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.name, "Spring rule")

    def test_financial_staff_keep_the_offer_edit_link(self) -> None:
        for role in ("admin", "billing"):
            with self.subTest(role=role):
                user = get_user_model().objects.create_user(email=f"promo-{role}@example.test", staff_role=role)
                self.client.force_login(user)
                edit_url = reverse("promotions:rule_update", kwargs={"pk": self.rule.pk})
                response = self.client.get(reverse("promotions:rule_list"))
                self.assertContains(response, edit_url)
                self.assertContains(self.client.get(edit_url), 'name="minimum_subtotal"')

    def test_coupon_campaign_filter_has_options_and_filters_records(self) -> None:
        self.coupon.campaign = self.campaign
        self.coupon.save(update_fields=["campaign"])
        Coupon.objects.create(code="UNRELATED", name="Unrelated coupon", discount_type="percent", discount_percent=5)
        inactive = PromotionCampaign.objects.create(
            name="Inactive campaign", slug="inactive-campaign", start_date=timezone.now(), is_active=False
        )
        response = self.client.get(reverse("promotions:coupon_list"), {"campaign": self.campaign.pk})
        self.assertContains(response, 'name="campaign"')
        self.assertContains(response, f'value="{self.campaign.pk}" selected')
        self.assertContains(response, self.campaign.name)
        self.assertNotContains(response, str(inactive.pk))
        self.assertContains(response, self.coupon.code)
        self.assertNotContains(response, "UNRELATED")

    def test_coupon_campaign_filter_rejects_a_malformed_identifier(self) -> None:
        response = self.client.get(reverse("promotions:coupon_list"), {"campaign": "not-a-uuid"})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.coupon.code)
        self.assertContains(response, "No records found")

    def test_offer_edit_preserves_all_supported_product_restrictions(self) -> None:
        for model, form_class in ((self.coupon, CouponForm), (self.rule, PromotionRuleForm)):
            with self.subTest(model=model):
                model.applies_to_all_products = False
                model.product_restrictions = {"excluded_product_types": ["domain"]}
                if isinstance(model, PromotionRule):
                    model.conditions = {"required_product_types": ["shared_hosting"]}
                model.save()
                original = form_class(instance=model)
                data = {field.name: field.value() if field.value() is not None else "" for field in original}
                data["name"] = "Only the name changes"
                form = form_class(data, instance=model)
                self.assertTrue(form.is_valid(), form.errors)
                form.save()
                model.refresh_from_db()
                self.assertEqual(model.product_restrictions, {"excluded_product_types": ["domain"]})
                if isinstance(model, PromotionRule):
                    self.assertEqual(model.conditions, {"required_product_types": ["shared_hosting"]})
