"""
Intent policy: which kinds of task an agent is scoped to, and which tools
each kind of task may use.

Classification here is deliberately simple and deterministic (whole-word /
whole-phrase keyword match on the USER'S request). It never looks at tool
output or retrieved content, so untrusted content cannot steer it.
"""

from __future__ import annotations

import re

from pydantic import BaseModel


class IntentSpec(BaseModel):
    keywords: list[str]
    allowed_tools: list[str]


class IntentPolicy(BaseModel):
    name: str
    intents: dict[str, IntentSpec]
    # If False (default), a request matching more than one intent is ambiguous
    # and is escalated instead of silently getting the union of their tools.
    allow_multiple_intents: bool = False

    def classify(self, request: str) -> list[str]:
        """Return the sorted labels of every intent whose keywords appear in `request`."""
        matched = []
        for label, spec in self.intents.items():
            for kw in spec.keywords:
                if re.search(rf"(?<!\w){re.escape(kw)}(?!\w)", request, re.IGNORECASE):
                    matched.append(label)
                    break
        return sorted(matched)
