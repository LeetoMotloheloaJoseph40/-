"""Security primitives used by gates: injection detection and trust policy."""

from eightgates.security.injection import InjectionFinding, PromptInjectionDetector
from eightgates.security.trust import TrustPolicy

__all__ = ["InjectionFinding", "PromptInjectionDetector", "TrustPolicy"]
