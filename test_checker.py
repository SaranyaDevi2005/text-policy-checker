import unittest
from checker import check


class TestEmailPrivacyChecker(unittest.TestCase):
    """Focused tests for email detection, redaction, and blocking."""

    # -------------------------------------------------------------------------
    # Email Detection Tests
    # -------------------------------------------------------------------------

    def test_detect_single_email(self):
        text = "Please reach out to user@example.com for support."
        result = check(text, policy="redact")
        self.assertEqual(result["types"], ["email"])
        self.assertEqual(result["redaction_count"], 1)

    def test_detect_multiple_emails(self):
        text = "Contact alice@example.org or bob@example.net for details."
        result = check(text, policy="redact")
        self.assertEqual(result["types"], ["email"])
        self.assertEqual(result["redaction_count"], 2)

    def test_detect_no_email(self):
        text = "This is a clean message without any email addresses."
        result = check(text, policy="redact")
        self.assertEqual(result["types"], [])
        self.assertEqual(result["redaction_count"], 0)

    def test_detect_various_email_formats(self):
        text = "Alerts to dev+ops@example.com and first.last@sub.example.co.uk."
        result = check(text, policy="redact")
        self.assertEqual(result["types"], ["email"])
        self.assertEqual(result["redaction_count"], 2)

    # -------------------------------------------------------------------------
    # Redaction Policy Tests
    # -------------------------------------------------------------------------

    def test_redact_single_email(self):
        text = "Send your resume to careers@example.com."
        result = check(text, policy="redact")
        self.assertEqual(result["decision"], "redacted")
        self.assertEqual(result["text"], "Send your resume to [EMAIL].")
        self.assertEqual(result["types"], ["email"])
        self.assertEqual(result["redaction_count"], 1)

    def test_redact_multiple_emails(self):
        text = "Send to support@example.com or sales@example.org."
        result = check(text, policy="redact")
        self.assertEqual(result["decision"], "redacted")
        self.assertEqual(result["text"], "Send to [EMAIL] or [EMAIL].")
        self.assertEqual(result["types"], ["email"])
        self.assertEqual(result["redaction_count"], 2)

    def test_redact_no_email_returns_original_text(self):
        text = "No sensitive information present."
        result = check(text, policy="redact")
        self.assertEqual(result["decision"], "allowed")
        self.assertEqual(result["text"], text)
        self.assertEqual(result["types"], [])
        self.assertEqual(result["redaction_count"], 0)

    def test_redact_preserves_surrounding_punctuation(self):
        text = "Inquiry: (info@example.com); Urgent: <help@example.net>!"
        result = check(text, policy="redact")
        self.assertEqual(result["text"], "Inquiry: ([EMAIL]); Urgent: <[EMAIL]>!")
        self.assertEqual(result["redaction_count"], 2)

    # -------------------------------------------------------------------------
    # Blocking Policy Tests
    # -------------------------------------------------------------------------

    def test_block_single_email(self):
        text = "Contact me at confidential@example.com directly."
        result = check(text, policy="block")
        self.assertEqual(result["decision"], "blocked")
        self.assertIsNone(result["text"])
        self.assertEqual(result["types"], ["email"])

    def test_block_multiple_emails(self):
        text = "Email admin@example.com or root@example.org."
        result = check(text, policy="block")
        self.assertEqual(result["decision"], "blocked")
        self.assertIsNone(result["text"])
        self.assertEqual(result["types"], ["email"])

    def test_block_no_email_allows_text(self):
        text = "Safe content that contains no email."
        result = check(text, policy="block")
        self.assertEqual(result["decision"], "allowed")
        self.assertEqual(result["text"], text)
        self.assertEqual(result["types"], [])
        self.assertEqual(result["redaction_count"], 0)

    def test_block_intentional_bug_redaction_count(self):
        # Intentional bug: redaction_count must equal the number of detected emails
        # even when the policy is "block".
        text = "Notify team1@example.com, team2@example.org, and team3@example.net."
        result = check(text, policy="block")
        self.assertEqual(result["decision"], "blocked")
        self.assertIsNone(result["text"])
        self.assertEqual(result["types"], ["email"])
        self.assertEqual(result["redaction_count"], 3)

    def test_block_regression_redaction_count_zero(self):
        text = "Contact user1@example.com or user2@example.org for inquiries."
        result = check(text, "block")
        self.assertEqual(result["decision"], "blocked")
        self.assertIsNone(result["text"])
        self.assertIn("email", result["types"])
        self.assertEqual(result["redaction_count"], 0)

    # -------------------------------------------------------------------------
    # Policy Validation
    # -------------------------------------------------------------------------

    def test_invalid_policy_raises_value_error(self):
        with self.assertRaises(ValueError):
            check("Hello user@example.com", policy="invalid_policy")


if __name__ == "__main__":
    unittest.main()
