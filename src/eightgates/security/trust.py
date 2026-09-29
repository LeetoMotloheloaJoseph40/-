"""
Trust policy: maps a content *source label* to a TrustLevel.

Trust is a property of where content came from, assigned by the developer —
never inferred from what the content says. Anything not explicitly listed
is UNTRUSTED (fail closed).
"""

from __future__ import annotations

from eightgates.core.models import TrustLevel

DEFAULT_SOURCE_TRUST: dict[str, TrustLevel] = {
    # The principal's own instruction channel. If a user pastes a web page or
    # document into their message, the application should label that part with
    # its real source (e.g. "document"), not "user".
    "user": TrustLevel.TRUSTED,
    "system": TrustLevel.TRUSTED,
    "memory": TrustLevel.PARTIALLY_TRUSTED,
}


class TrustPolicy:
    def __init__(
        self,
        mapping: dict[str, TrustLevel] | None = None,
        default: TrustLevel = TrustLevel.UNTRUSTED,
    ):
        self.mapping = dict(DEFAULT_SOURCE_TRUST if mapping is None else mapping)
        self.default = default

    def resolve(self, source: str) -> TrustLevel:
        """Exact match first, then the prefix before ':' (so 'tool:x' -> 'tool')."""
        if source in self.mapping:
            return self.mapping[source]
        prefix = source.split(":", 1)[0]
        return self.mapping.get(prefix, self.default)
