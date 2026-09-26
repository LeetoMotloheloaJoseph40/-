"""
Identity subsystem.

AgentIdentity/UserIdentity themselves live in eightgates.core.models
(they are domain models, not identity-subsystem logic). This package
holds the machinery for verifying identities: the registry for now, with
room for authentication.py / credentials.py / roles.py in a later stage.
"""

from eightgates.identity.registry import IdentityRegistry

__all__ = ["IdentityRegistry"]
