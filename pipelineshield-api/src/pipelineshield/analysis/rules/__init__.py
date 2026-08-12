"""High-severity pipeline weakness rule pack for PipelineShield.

Provides:
  - Violation rules: hardcoded secrets, expression injection, pwn-request,
    unpinned action references, missing/write-all permissions.
  - Presence detectors: one per control category, driven by
    data/tool_signatures.json.

Usage::

    from pipelineshield.analysis.rules import build_default_registry

    registry = build_default_registry()
    # or with a custom RuleRegistry:
    registry = RuleRegistry()
    register_all_rules(registry)

No FastAPI, SQLAlchemy, HTTP, or LLM imports anywhere in this package.
"""
from __future__ import annotations

from pipelineshield.analysis.rule_engine.registry import RuleRegistry

from .hardcoded_secret import HardcodedSecretRule
from .injection import ExpressionInjectionRule
from .least_privilege import LeastPrivilegeRule
from .presence import SignatureLoadError, build_presence_rules, load_tool_signatures
from .pwn_request import PwnRequestRule
from .supply_chain import UnpinnedActionRule

__all__ = [
    "HardcodedSecretRule",
    "ExpressionInjectionRule",
    "LeastPrivilegeRule",
    "PwnRequestRule",
    "UnpinnedActionRule",
    "SignatureLoadError",
    "build_default_registry",
    "register_all_rules",
]


def register_all_rules(registry: RuleRegistry) -> None:
    """Register all WO-016 rules into *registry*.

    Call once at application startup before any concurrent evaluation.
    Raises SignatureLoadError if the tool signature file cannot be loaded.
    """
    # Violation / behavioural rules
    registry.register(HardcodedSecretRule())
    registry.register(ExpressionInjectionRule())
    registry.register(PwnRequestRule())
    registry.register(UnpinnedActionRule())
    registry.register(LeastPrivilegeRule())

    # Presence detectors — one per category, data-driven
    signatures = load_tool_signatures()
    for presence_rule in build_presence_rules(signatures):
        registry.register(presence_rule)


def build_default_registry() -> RuleRegistry:
    """Build and return a RuleRegistry populated with all WO-016 rules."""
    registry = RuleRegistry()
    register_all_rules(registry)
    return registry
