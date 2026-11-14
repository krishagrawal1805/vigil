"""
Security Capability Registry
============================
Provides dynamic capability discovery for autonomous security testing.
Maps attack surface evidence and endpoints to specialized security capabilities,
controlled tools, and methodology skills.
"""

from .registry import (
    SecurityCapability,
    SecurityCapabilityRegistry,
    get_capability_registry,
    query_security_capabilities,
)

__all__ = [
    "SecurityCapability",
    "SecurityCapabilityRegistry",
    "get_capability_registry",
    "query_security_capabilities",
]

