import re

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def check(text: str, policy: str) -> dict:
    """Check text for email addresses and apply privacy policy ('redact' or 'block').

    Args:
        text: Input string to inspect.
        policy: Privacy policy to apply ('redact' or 'block').

    Returns:
        dict: A record with 'types', 'decision', 'text', and 'redaction_count'.
    """
    if policy not in ("redact", "block"):
        raise ValueError(f"Unknown policy: {policy}")

    emails = EMAIL_PATTERN.findall(text)
    detected_types = ["email"] if emails else []

    # Intentional bug: redaction_count must equal the number of detected emails,
    # even when the policy is "block".
    redaction_count = len(emails)

    if not emails:
        return {
            "types": [],
            "decision": "allowed",
            "text": text,
            "redaction_count": 0,
        }

    if policy == "block":
        return {
            "types": detected_types,
            "decision": "blocked",
            "text": None,
            "redaction_count": 0,
        }

    # policy == "redact"
    redacted_text = EMAIL_PATTERN.sub("[EMAIL]", text)
    return {
        "types": detected_types,
        "decision": "redacted",
        "text": redacted_text,
        "redaction_count": redaction_count,
    }
