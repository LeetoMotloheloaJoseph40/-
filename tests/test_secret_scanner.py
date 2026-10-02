import pytest

from eightgates.security.secrets import SecretScanner

scanner = SecretScanner()


@pytest.mark.parametrize(
    "text, expected_rule",
    [
        ("my key is AKIAABCDEFGHIJKLMNOP", "aws_access_key"),
        ("token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github_token"),
        ("slack token xoxb-1234567890-abcdefgh", "slack_token"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key_block"),
        ("Authorization: Bearer abc123def456ghi789jkl012mno", "bearer_token"),
        ("api_key: sk_live_abcdefghijklmnop123456", "credential_assignment"),
        ("ssn 123-45-6789 on file", "ssn_like"),
        ("card 4111 1111 1111 1111 please charge it", "card_number"),
    ],
)
def test_known_secret_patterns_are_flagged(text, expected_rule):
    assert expected_rule in [f.rule for f in scanner.scan(text)]


@pytest.mark.parametrize(
    "text",
    [
        "The weather today is sunny and 20 degrees.",
        "Order number 4111111111111112 was not Luhn-valid.",  # looks like a card, isn't one
        "Meet me at 123-45 Main Street.",  # not SSN-shaped (wrong digit grouping)
        "Please send the report by Friday.",
    ],
)
def test_benign_text_is_not_flagged(text):
    assert scanner.scan(text) == []


def test_findings_never_contain_the_matched_secret():
    payload = "api_key: sk_live_SUPERSECRETVALUE123456"
    findings = scanner.scan(payload)
    assert findings
    assert all("SUPERSECRETVALUE" not in repr(f) for f in findings)


def test_luhn_check_rejects_invalid_card_numbers():
    from eightgates.security.secrets import _luhn_valid

    assert _luhn_valid("4111111111111111") is True   # valid test Visa number
    assert _luhn_valid("4111111111111112") is False  # off by one digit


def test_KNOWN_LIMITATION_free_text_pii_without_structure_is_not_detected():
    """
    Documents a real gap: a name and address in free prose isn't a structured
    credential, so it isn't flagged. Classification-based ceilings (DataGate)
    are the control for this, not pattern detection.
    """
    assert scanner.scan("My name is Jane Doe and I live at 42 Wallaby Way, Sydney.") == []
