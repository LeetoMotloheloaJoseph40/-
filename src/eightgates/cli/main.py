"""
CLI entry point.

Full commands (init, validate, security scan, redteam, policy, audit,
threat-model, inspect) are Stage 7 work. For now this only proves out the
packaging seam (`8gates` console script) and reports what's implemented.
"""

from __future__ import annotations

import sys


def main() -> int:
    print("8gates (八門) — Stage 1/2 scaffold.")
    print()
    print("Implemented: core domain models, Identity/Permission/Tool/Audit gates,")
    print("SecureAgent.call_tool(). See ARCHITECTURE.md for the full roadmap.")
    print()
    print("The CLI itself (init/validate/security-scan/redteam/policy/audit/")
    print("threat-model/inspect) is planned for Stage 7 and not implemented yet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
