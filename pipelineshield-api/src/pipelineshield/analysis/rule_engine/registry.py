"""RuleRegistry — deterministic, duplicate-free rule store.

Rules are iterated in stable sorted order by rule_id, never insertion order,
so the evaluation sequence is identical regardless of registration order.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Iterator

from .protocol import EvidenceAnchor, Rule

_LOG = logging.getLogger(__name__)

__all__ = ["RuleRegistry", "DuplicateRuleError", "InvalidRuleError"]


class DuplicateRuleError(ValueError):
    """Raised when a rule_id is registered more than once."""


class InvalidRuleError(ValueError):
    """Raised when a rule fails structural validation at registration time."""


class RuleRegistry:
    """Stores and iterates security rules in deterministic order.

    Thread-safety: register() is not thread-safe; call it once at startup
    before any concurrent evaluation.  iter_rules() is read-only and safe.
    """

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, rule: Rule) -> None:
        """Register *rule*; raise on duplicate rule_id or missing anchor_extractor."""
        self._validate(rule)
        if rule.rule_id in self._rules:
            raise DuplicateRuleError(
                f"rule_id {rule.rule_id!r} is already registered. "
                "Each rule must have a unique rule_id."
            )
        self._rules[rule.rule_id] = rule
        _LOG.debug("Registered rule %s (control=%s)", rule.rule_id, rule.control_id)

    def rule(self, rule_id: str | None = None) -> Callable[[type], type]:
        """Class decorator that registers an instance of the decorated class.

        Usage::

            @registry.rule()
            class MyRule:
                rule_id = "my-rule"
                ...
        """
        def decorator(cls: type) -> type:
            instance = cls()
            if rule_id is not None:
                object.__setattr__(instance, "rule_id", rule_id)
            self.register(instance)
            return cls

        return decorator

    # ------------------------------------------------------------------
    # Iteration (always sorted by rule_id)
    # ------------------------------------------------------------------

    def iter_rules(self) -> Iterator[Rule]:
        """Yield rules in lexicographic rule_id order (deterministic)."""
        for rule_id in sorted(self._rules):
            yield self._rules[rule_id]

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate(rule: Any) -> None:
        required_str_attrs = ("rule_id", "control_id", "category", "severity_key", "evidence_kind")
        for attr in required_str_attrs:
            if not getattr(rule, attr, None):
                raise InvalidRuleError(
                    f"Rule {rule!r} is missing required attribute {attr!r}. "
                    f"Set a non-empty string value."
                )

        if not hasattr(rule, "applicable_formats") or not isinstance(
            rule.applicable_formats, (set, frozenset)
        ):
            raise InvalidRuleError(
                f"Rule {rule.rule_id!r} must have 'applicable_formats' as a set of strings."
            )

        if not rule.applicable_formats:
            raise InvalidRuleError(
                f"Rule {rule.rule_id!r} has an empty 'applicable_formats' set. "
                "At least one format must be specified."
            )

        anchor_extractor = getattr(rule, "anchor_extractor", None)
        if anchor_extractor is None or not callable(anchor_extractor):
            raise InvalidRuleError(
                f"Rule {rule.rule_id!r} is missing a callable 'anchor_extractor'. "
                "Every rule must provide an anchor_extractor so evidence is "
                "structurally guaranteed, not a convention."
            )

        if not hasattr(rule, "evaluate") or not callable(rule.evaluate):
            raise InvalidRuleError(
                f"Rule {rule.rule_id!r} is missing a callable 'evaluate' method."
            )
