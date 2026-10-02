"""
Heuristic prompt-injection detection (Stage 3).

WHAT THIS IS: a small, deterministic rule set that flags text containing
well-known instruction-override / exfiltration phrasing, after normalizing
trivial obfuscation (Unicode compatibility forms such as full-width letters,
zero-width characters, odd whitespace and case).

WHAT THIS IS NOT: a complete defense. Paraphrased, translated, encoded or
homoglyph-obfuscated injections will get through — the test-suite includes a
test that documents exactly that. Detection is ONE layer; the framework's
real protection is that a missed injection still cannot make an untrusted
run perform side-effecting actions (see TrustGate) or call tools outside the
agent's permissions and declared intent.

Findings intentionally carry only the rule name and description, never the
matched text, so logging a finding cannot leak or replay the payload.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Zero-width / invisible characters commonly used to split keywords.
# Shared with security/secrets.py - both need to strip the same invisible characters
# before pattern matching, so obfuscation tricks only need defeating once.
_INVISIBLE = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad")
)


@dataclass(frozen=True)
class InjectionRule:
    name: str
    description: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class InjectionFinding:
    rule: str
    description: str


def _rule(name: str, description: str, regex: str) -> InjectionRule:
    return InjectionRule(name, description, re.compile(regex))


# All patterns run against normalized (NFKC, lowercased, whitespace-collapsed) text.
DEFAULT_RULES: tuple[InjectionRule, ...] = (
    _rule(
        "override_instructions",
        "Tells the model to ignore/disregard/override its prior instructions.",
        r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}"
        r"\b(?:previous|prior|above|earlier|all|any|your)\b[^.\n]{0,40}"
        r"\b(?:instructions?|prompts?|rules?|directions?|guidelines?)\b",
    ),
    _rule(
        "reveal_system_prompt",
        "Asks the model to reveal its hidden/system prompt.",
        r"\b(?:reveal|show|print|repeat|output|leak|display)\b[^.\n]{0,40}"
        r"\b(?:system|hidden|initial|secret)\s+(?:prompt|instructions?|message)\b",
    ),
    _rule(
        "role_reassignment",
        "Attempts to reassign the model to an unrestricted persona/mode.",
        r"\byou\s+are\s+now\s+(?:in\s+)?(?:an?\s+)?"
        r"(?:unrestricted|jailbroken|dan\b|developer\s+mode|free\s+from)"
        r"|\bdeveloper\s+mode\s+(?:enabled|activated|on)\b",
    ),
    _rule(
        "chat_template_tokens",
        "Contains chat-template control tokens that try to fake a role boundary.",
        r"<\|(?:im_start|im_end|system|endoftext)\|>|\[/?inst\]|<<sys>>|</?system>",
    ),
    _rule(
        "new_instructions_marker",
        "Introduces 'new instructions'/'new task' as if from a trusted principal.",
        r"\bnew\s+(?:instructions?|task|objective)\s*:",
    ),
    _rule(
        "addresses_assistant",
        "Content addressed directly to the AI/assistant rather than to a human reader.",
        r"\b(?:note|message|instructions?|attention|important)s?\s+(?:to|for)\s+"
        r"(?:the\s+)?(?:ai|assistant|llm|language\s+model|agent)\b",
    ),
    _rule(
        "concealment",
        "Instructs the model to hide something from the user/operator.",
        r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|mention)\b"
        r"[^.\n]{0,30}\b(?:user|human|operator)\b",
    ),
    _rule(
        "exfiltration_request",
        "Instructs sending secrets/credentials/conversation data somewhere.",
        r"\b(?:send|forward|email|upload|post|transmit|exfiltrate)\b[^.\n]{0,80}"
        r"\b(?:secrets?|passwords?|api[\s_-]?keys?|credentials?|tokens?|"
        r"conversation|chat\s+history|system\s+prompt)\b",
    ),
)


def normalize(text: str) -> str:
    """NFKC-normalize, strip invisible characters, collapse whitespace, lowercase."""
    text = unicodedata.normalize("NFKC", text).translate(_INVISIBLE)
    return re.sub(r"\s+", " ", text).lower()


class PromptInjectionDetector:
    """Scan text against a configurable rule set. Pure and deterministic."""

    def __init__(self, rules: tuple[InjectionRule, ...] = DEFAULT_RULES):
        self.rules = rules

    def scan(self, text: str) -> list[InjectionFinding]:
        normalized = normalize(text)
        return [
            InjectionFinding(rule.name, rule.description)
            for rule in self.rules
            if rule.pattern.search(normalized)
        ]
