"""
Tests for feedback category and sentiment detection helpers.

Regression guard: these tests capture the chaos-monkey finding that
single-word keywords like 'add' or 'down' matched as substrings inside
longer words such as 'address' or 'download', producing false-positive
category assignments.
"""

from django.test import TestCase

from apps.customers.tasks import _detect_feedback_category, _detect_feedback_sentiment


class TestFeedbackCategoryDetection(TestCase):
    """_detect_feedback_category() — keyword-based category detection."""

    # ---------------------------------------------------------------------------
    # Happy-path category detection
    # ---------------------------------------------------------------------------

    def test_billing_category_invoice(self) -> None:
        self.assertEqual(_detect_feedback_category("I need an invoice refund"), "billing")

    def test_billing_category_payment(self) -> None:
        self.assertEqual(_detect_feedback_category("I have a problem with my payment"), "billing")

    def test_technical_category_server(self) -> None:
        self.assertEqual(_detect_feedback_category("The server is giving an error"), "technical")

    def test_technical_category_error_keyword(self) -> None:
        self.assertEqual(_detect_feedback_category("I keep getting a dns error"), "technical")

    def test_praise_category_thank(self) -> None:
        self.assertEqual(_detect_feedback_category("Great service, thank you!"), "praise")

    def test_praise_category_excellent(self) -> None:
        self.assertEqual(_detect_feedback_category("Excellent support, very happy!"), "praise")

    def test_complaint_category_terrible(self) -> None:
        self.assertEqual(_detect_feedback_category("This is terrible and I am angry"), "complaint")

    def test_complaint_category_disappointed(self) -> None:
        self.assertEqual(_detect_feedback_category("Very disappointed with the service"), "complaint")

    def test_general_fallback_no_keywords(self) -> None:
        self.assertEqual(_detect_feedback_category("Just checking in"), "general")

    def test_general_fallback_empty_string(self) -> None:
        self.assertEqual(_detect_feedback_category(""), "general")

    # ---------------------------------------------------------------------------
    # Romanian keyword detection
    # ---------------------------------------------------------------------------

    def test_romanian_praise_multumesc(self) -> None:
        self.assertEqual(_detect_feedback_category("Multumesc pentru ajutor"), "praise")

    def test_romanian_billing_factura(self) -> None:
        self.assertEqual(_detect_feedback_category("Am o problema cu factura"), "billing")

    # ---------------------------------------------------------------------------
    # Word-boundary false-positive regression tests
    # ---------------------------------------------------------------------------

    def test_add_does_not_match_address(self) -> None:
        """'add' as a keyword must NOT fire on 'address' — word-boundary check.

        Regression: substring match would have classified 'address' as
        'feature_request' because 'add' appears inside 'address'.
        """
        result = _detect_feedback_category("Please update my address details")
        self.assertNotEqual(result, "feature_request")

    def test_down_does_not_match_download(self) -> None:
        """'down' must NOT match 'download' — word-boundary check.

        Regression: 'download' contains 'down', which is a 'technical' keyword.
        The correct behaviour is that 'invoice' wins (billing) or the result is
        not 'technical' when no server/error context is present.
        """
        result = _detect_feedback_category("I need to download my invoices")
        # 'invoice' (billing keyword) is present → should NOT be classified as technical
        self.assertNotEqual(result, "technical")

    def test_add_standalone_matches_feature_request(self) -> None:
        """The word 'add' by itself should still match feature_request."""
        result = _detect_feedback_category("Please add a new API endpoint")
        self.assertEqual(result, "feature_request")

    # ---------------------------------------------------------------------------
    # Multi-word phrase matching
    # ---------------------------------------------------------------------------

    def test_multiword_phrase_would_be_nice(self) -> None:
        """Multi-word phrases like 'would be nice' match via substring."""
        result = _detect_feedback_category("It would be nice to have an API")
        self.assertEqual(result, "feature_request")

    def test_feature_request_suggest_keyword(self) -> None:
        result = _detect_feedback_category("I suggest you implement an export feature")
        self.assertEqual(result, "feature_request")

    # ---------------------------------------------------------------------------
    # Highest-score-wins when multiple categories match
    # ---------------------------------------------------------------------------

    def test_highest_score_wins(self) -> None:
        """When two categories match, the one with more keyword hits wins."""
        # 'invoice payment error' → billing has 2 hits (invoice, payment), technical has 1 (error)
        result = _detect_feedback_category("invoice payment error")
        self.assertEqual(result, "billing")


class TestFeedbackSentimentDetection(TestCase):
    """_detect_feedback_sentiment() — positive / negative / neutral classification."""

    def test_positive_sentiment_great(self) -> None:
        self.assertEqual(_detect_feedback_sentiment("Great service, love it!"), "positive")

    def test_positive_sentiment_excellent(self) -> None:
        self.assertEqual(_detect_feedback_sentiment("excellent support thank you"), "positive")

    def test_negative_sentiment_terrible(self) -> None:
        self.assertEqual(_detect_feedback_sentiment("Terrible experience, broken service"), "negative")

    def test_negative_sentiment_awful(self) -> None:
        self.assertEqual(_detect_feedback_sentiment("awful response, hate this"), "negative")

    def test_neutral_sentiment_no_keywords(self) -> None:
        self.assertEqual(_detect_feedback_sentiment("I have a question about my account"), "neutral")

    def test_neutral_sentiment_equal_positive_negative(self) -> None:
        """Equal positive and negative word counts must resolve to neutral."""
        self.assertEqual(_detect_feedback_sentiment("great but terrible"), "neutral")

    def test_punctuation_stripped_before_matching(self) -> None:
        """Words with trailing punctuation must still match ('great!' → 'great')."""
        self.assertEqual(_detect_feedback_sentiment("great!"), "positive")
        self.assertEqual(_detect_feedback_sentiment("terrible,"), "negative")

    def test_romanian_positive_multumesc(self) -> None:
        self.assertEqual(_detect_feedback_sentiment("multumesc excelent bravo"), "positive")

    def test_romanian_negative_nemultumit(self) -> None:
        self.assertEqual(_detect_feedback_sentiment("nemultumit prost rau"), "negative")
