"""The checkout progress labels come from the Romanian catalog, not an English fallback."""

from django.test import SimpleTestCase
from django.utils.translation import override

from apps.orders.views import ORDER_STEPS


class OrderStepsTranslationTests(SimpleTestCase):
    def test_every_progress_label_is_translated_into_romanian(self) -> None:
        with override("ro"):
            labels = [str(step["label"]) for step in ORDER_STEPS]
        self.assertEqual(labels, ["Selectarea produsului", "Revizuire coș", "Plată", "Confirmare"])
