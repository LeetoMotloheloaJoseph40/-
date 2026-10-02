"""
Heuristic secret / sensitive-data detection (Stage 4).

Same philosophy as security/injection.py: a small, deterministic rule set,
not a complete DLP solution. Findings carry only the rule name/description,
never the matched text, so a finding can never leak the secret it found.

WHAT THIS CATCHES: common credential formats (cloud/provider tokens, private
key blocks, "key: value"-style assignments) and Luhn-valid card-number-shaped
digit sequences.

WHAT THIS DOES NOT CATCH: anything not matching these shapes — a secret
pasted with unusual formatting, a novel token format, or free-text PII that
isn't a structured credential. The SSN-style rule is US-specific and prone
to false positives on any 9-digit sequence; it is intentionally narrow.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from eightgates.security.injection import _INVISIBLE


@dataclass(frozen=True)
class SecretRule:
    name: str
    description: str
    pattern: re.Pattern[str] | None  # None for rules implemented as functions (e.g. Luhn)


@dataclass(frozen=True)
class SecretFinding:
    rule: str
    description: str


def _rule(name: str, description: str, regex: str, flags: int = 0) -> SecretRule:
    return SecretRule(name, description, re.compile(regex, flags))


_STATIC_RULES: tuple[SecretRule, ...] = (
    _rule("aws_access_key", "AWS access key ID.", r"\bAKIA[0-9A-Z]{16}\b"),
    _rule("github_token", "GitHub personal access / app token.", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    _rule("slack_token", "Slack API token.", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    _rule(
        "private_key_block",
        "A PEM-format private key block.",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----",
    ),
    _rule(
        "bearer_token",
        "An HTTP bearer/authorization token.",
        r"\bbearer\s+[a-z0-9\-_.=]{20,}\b",
        re.IGNORECASE,
    ),
    _rule(
        "credential_assignment",
        "A variable assignment that looks like a password/API key/secret/token.",
        r"\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9\-_/+]{12,}",
        re.IGNORECASE,
    ),
    _rule(
        "ssn_like",
        "A US Social Security Number-shaped sequence (###-##-####). High false-positive rate.",
        r"\b\d{3}-\d{2}-\d{4}\b",
    ),
)


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _scan_card_numbers(text: str) -> bool:
    for match in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True
    return False


def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE)


class SecretScanner:
    """Scan text for secret/sensitive-data patterns. Pure and deterministic."""

    def __init__(self, rules: tuple[SecretRule, ...] = _STATIC_RULES):
        self.rules = rules

    def scan(self, text: str) -> list[SecretFinding]:
        normalized = normalize(text)
        findings = [
            SecretFinding(rule.name, rule.description)
            for rule in self.rules
            if rule.pattern is not None and rule.pattern.search(normalized)
        ]
        if _scan_card_numbers(normalized):
            findings.append(
                SecretFinding("card_number", "A Luhn-valid payment card number sequence.")
            )
        return findings
