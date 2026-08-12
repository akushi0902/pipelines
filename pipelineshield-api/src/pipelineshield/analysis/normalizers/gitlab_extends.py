"""GitLab CI extends chain resolver.

Design:
  - Build a directed graph (job → parent list) from all extends declarations.
  - Detect cycles via DFS with white/gray/black colouring; record them as
    UnresolvedFragment(kind='extends_cycle') rather than raising.
  - Topological-sort the acyclic subgraph so parents are merged before
    their children.
  - Apply GitLab merge semantics:
      • Maps are deep-merged (child wins on key conflict).
      • Arrays are replaced entirely — GitLab never merges arrays.
      • Scalar values from child override scalar values from parent.
  - Missing parent references (job not found in the document) are recorded
    as UnresolvedFragment(kind='extends_missing').

No outbound I/O, no FastAPI, no HTTP.
"""
from __future__ import annotations

import copy
from typing import Any

from ruamel.yaml.comments import CommentedMap, CommentedSeq  # type: ignore[import-untyped]

from pipelineshield.analysis.ir.pipeline_ir import UnresolvedFragment

__all__ = ["ExtendsMerger"]

_ABSENT = object()

# ---------------------------------------------------------------------------
# GitLab deep-merge semantics
# ---------------------------------------------------------------------------


def _deep_merge(base: Any, override: Any) -> Any:
    """Merge *override* into *base* with GitLab semantics.

    - Both mappings → recursively merge (child key wins).
    - Either is a sequence → *override* replaces *base* entirely.
    - Otherwise → *override* wins.
    """
    if isinstance(base, (dict, CommentedMap)) and isinstance(
        override, (dict, CommentedMap)
    ):
        result = CommentedMap()
        for k in base:
            result[k] = copy.deepcopy(base[k])
        for k in override:
            if k in result and isinstance(result[k], (dict, CommentedMap)) and isinstance(
                override[k], (dict, CommentedMap)
            ):
                result[k] = _deep_merge(result[k], override[k])
            else:
                result[k] = copy.deepcopy(override[k])
        return result
    # Sequences: child replaces parent entirely (GitLab array semantics)
    return copy.deepcopy(override)


# ---------------------------------------------------------------------------
# Dependency graph helpers
# ---------------------------------------------------------------------------


def _get_parents(job_node: Any) -> list[str]:
    """Return the list of parent job names declared in *extends*."""
    if not isinstance(job_node, (dict, CommentedMap)):
        return []
    extends = job_node.get("extends", _ABSENT)
    if extends is _ABSENT:
        return []
    if isinstance(extends, str):
        return [extends]
    if isinstance(extends, (list, CommentedSeq)):
        return [str(x) for x in extends]
    return []


def _build_graph(jobs: dict[str, Any]) -> dict[str, list[str]]:
    return {name: _get_parents(node) for name, node in jobs.items()}


# ---------------------------------------------------------------------------
# Cycle detection (DFS colouring)
# ---------------------------------------------------------------------------

_WHITE = 0
_GRAY = 1
_BLACK = 2


def _find_cyclic_nodes(graph: dict[str, list[str]]) -> set[str]:
    """Return all job names that participate in at least one cycle."""
    color: dict[str, int] = {n: _WHITE for n in graph}
    in_cycle: set[str] = set()

    def _dfs(node: str, stack: list[str]) -> None:
        color[node] = _GRAY
        stack.append(node)
        for parent in graph.get(node, []):
            if parent not in color:
                continue
            if color[parent] == _GRAY:
                # Back edge — everything from parent's position to here is cyclic
                idx = stack.index(parent)
                for n in stack[idx:]:
                    in_cycle.add(n)
            elif color[parent] == _WHITE:
                _dfs(parent, stack)
        stack.pop()
        color[node] = _BLACK

    for name in list(graph):
        if color[name] == _WHITE:
            _dfs(name, [])

    return in_cycle


# ---------------------------------------------------------------------------
# Topological sort
# ---------------------------------------------------------------------------


def _topological_order(
    graph: dict[str, list[str]], nodes: set[str]
) -> list[str]:
    """Return *nodes* in topological order (parents before children).

    Unknown parent references (not in *nodes*) are ignored.
    """
    visited: set[str] = set()
    order: list[str] = []

    def _visit(name: str) -> None:
        if name in visited:
            return
        visited.add(name)
        for parent in graph.get(name, []):
            if parent in nodes:
                _visit(parent)
        order.append(name)

    for name in nodes:
        _visit(name)
    return order


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class ExtendsMerger:
    """Resolves all extends chains across the jobs in a GitLab CI document.

    Usage::

        merger = ExtendsMerger(jobs, unresolved_list)
        resolved = merger.resolve_all()
        # resolved is {job_name: merged_node, ...}
    """

    def __init__(
        self,
        jobs: dict[str, Any],
        unresolved: list[UnresolvedFragment],
    ) -> None:
        self._jobs = jobs
        self._unresolved = unresolved

    def resolve_all(self) -> dict[str, Any]:
        """Return a dict of job_name → merged CommentedMap.

        Jobs that participate in a cycle or reference a missing parent are
        returned with their own node unmodified and an UnresolvedFragment
        appended to the shared *unresolved* list.
        """
        graph = _build_graph(self._jobs)
        cyclic = _find_cyclic_nodes(graph)

        # Record cycles as unresolved
        for name in sorted(cyclic):
            self._unresolved.append(
                UnresolvedFragment(
                    kind="extends_cycle",
                    locator=f"jobs.{name}.extends",
                    reason=(
                        f"Job '{name}' participates in an extends cycle; "
                        "extends resolution requires a network call or cross-file "
                        "context — marked Not Assessable."
                    ),
                )
            )

        # Only attempt resolution for acyclic jobs
        resolvable_names = set(self._jobs) - cyclic
        clean_graph = {
            k: [p for p in v if p not in cyclic]
            for k, v in graph.items()
            if k not in cyclic
        }
        order = _topological_order(clean_graph, resolvable_names)

        resolved: dict[str, Any] = {}

        for name in order:
            raw_node = self._jobs[name]
            parents = clean_graph.get(name, [])

            if not parents:
                # No extends — copy as-is (minus extends key)
                node = copy.deepcopy(raw_node)
                if isinstance(node, (dict, CommentedMap)):
                    node.pop("extends", None)
                resolved[name] = node
                continue

            # Build cumulative merged parent
            merged_parent: Any = CommentedMap()
            for parent_name in parents:
                if parent_name not in resolved:
                    # Parent from a remote include or missing definition
                    self._unresolved.append(
                        UnresolvedFragment(
                            kind="extends_missing",
                            locator=f"jobs.{name}.extends",
                            reason=(
                                f"Job '{name}' extends '{parent_name}', which is "
                                "not present in this document (may come from a "
                                "remote include) — marked Not Assessable."
                            ),
                        )
                    )
                    continue
                merged_parent = _deep_merge(merged_parent, resolved[parent_name])

            # Child wins over merged parents
            child_node = copy.deepcopy(raw_node)
            if isinstance(child_node, (dict, CommentedMap)):
                child_node.pop("extends", None)
            merged_final = _deep_merge(merged_parent, child_node)
            resolved[name] = merged_final

        # Cyclic jobs pass through unmodified
        for name in cyclic:
            resolved[name] = copy.deepcopy(self._jobs[name])

        return resolved
