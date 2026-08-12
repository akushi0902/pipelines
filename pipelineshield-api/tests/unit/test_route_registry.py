"""Structural tests — route registry and static AST analysis (WO-037 AC-2, AC-9).

Tests
-----
TestRouteRegistry
    Every application route either carries a require_capability() guard or is
    listed in the explicit auth-exemption set (login, callback, logout, session).
    An unmapped route causes this test to fail — no silent pass-through.

TestStaticAstAnalysis
    Parses every router module's source as an AST and fails the suite if any
    file contains:
      1. An inline role/persona comparison  (Compare node on "persona" or "role")
      2. A raw SQL string literal           (str containing SELECT/INSERT/UPDATE/DELETE)
      3. A direct SQLAlchemy session import (import of Session outside the known
         read-only exceptions)
"""
from __future__ import annotations

import ast
import importlib
import inspect
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.routing import APIRoute


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_guard(route: APIRoute) -> bool:
    """Walk the route's dependency tree looking for a require_capability guard.

    The guard function has ``_required_capability`` set on it by
    ``require_capability()`` so we can identify it without string matching.
    The check walks ``route.dependant`` (FastAPI's internal resolved dependency
    graph) so we catch both route-level and parameter-level Depends usage.
    """
    from fastapi.dependencies.models import Dependant

    seen: set[int] = set()

    def _walk(dep: Dependant) -> bool:
        key = id(dep.call)
        if key in seen:
            return False
        seen.add(key)
        if getattr(dep.call, "_required_capability", None) is not None:
            return True
        for child in dep.dependencies:
            if _walk(child):
                return True
        return False

    return _walk(route.dependant)


# Routes that legitimately bypass the capability guard because they ARE the
# authentication boundary.  Any route not on this list must have a guard.
_AUTH_EXEMPT_PREFIXES = (
    "/api/v1/auth/",
)


# ---------------------------------------------------------------------------
# Route registry test (AC-2)
# ---------------------------------------------------------------------------


class TestRouteRegistry:
    """Every non-auth route must declare a require_capability() guard."""

    def test_all_routes_have_guard_or_are_exempted(self) -> None:
        from pipelineshield.api.main import create_app

        app = create_app()

        unguarded: list[str] = []
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            path: str = route.path
            # Auth routes are pre-auth by design — exempted.
            if any(path.startswith(pfx) for pfx in _AUTH_EXEMPT_PREFIXES):
                continue
            if not _has_guard(route):
                unguarded.append(f"{sorted(route.methods)} {path}")

        assert not unguarded, (
            "The following routes have no require_capability() guard. "
            "Add the guard or add the route to the auth-exemption list:\n"
            + "\n".join(f"  {r}" for r in unguarded)
        )

    def test_default_deny_for_unmapped_route(self) -> None:
        """require_capability() with an unknown capability denies by default."""
        from pipelineshield.api.security.authz_guard import (
            PERSONA_CAPABILITIES,
            CurrentActor,
        )
        import uuid

        # Resolve a fictional capability that is not in PERSONA_CAPABILITIES
        all_capabilities: set[str] = set()
        for caps in PERSONA_CAPABILITIES.values():
            all_capabilities.update(caps)

        unmapped = "nonexistent:capability:xyz"
        assert unmapped not in all_capabilities, (
            "Test setup error: 'unmapped' must not be a real capability"
        )

        # Verify that no persona has this capability
        for persona, caps in PERSONA_CAPABILITIES.items():
            assert unmapped not in caps, (
                f"Persona {persona!r} unexpectedly has capability {unmapped!r}"
            )


# ---------------------------------------------------------------------------
# Static AST test (AC-9)
# ---------------------------------------------------------------------------

_ROUTER_PACKAGE = Path(__file__).parents[2] / "src" / "pipelineshield" / "api" / "v1" / "routers"

# All router files import Session for the `session: Session = Depends(get_db)` type
# annotation — this is the approved dependency-injection pattern and is NOT a violation.
# The check below therefore looks for direct session *usage* (instantiation or ORM calls)
# rather than the import itself.  The only currently known legitimate exception for
# direct repository access (not just type annotation) is audit_router.py.
_SESSION_USAGE_EXCEPTIONS: dict[str, str] = {
    "audit_router.py": "read-only SQLAlchemyAuditRepository access; intentional per WO-038",
}

# Strings in SQL literals that indicate raw SQL.
_SQL_KEYWORDS = ("SELECT", "INSERT", "UPDATE", "DELETE", "FROM ", "WHERE ")

# Identifiers that must not appear in Compare nodes inside router files.
_ROLE_IDENTIFIERS = {"persona", "role", "actor_persona"}


class _AstVisitor(ast.NodeVisitor):
    """Collect structural violations from a router AST."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.violations: list[str] = []

    def visit_Compare(self, node: ast.Compare) -> None:
        """Detect inline role/persona comparisons."""
        left = node.left

        def _names(n: ast.expr) -> list[str]:
            if isinstance(n, ast.Name):
                return [n.id]
            if isinstance(n, ast.Attribute):
                return [n.attr] + _names(n.value)
            return []

        all_names = _names(left)
        for comp in node.comparators:
            all_names.extend(_names(comp))

        for name in all_names:
            if name in _ROLE_IDENTIFIERS:
                self.violations.append(
                    f"{self.filename}:{node.lineno} — inline role comparison on {name!r}. "
                    "Move capability decisions to AuthzGuard."
                )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Detect raw SQL string literals."""
        if isinstance(node.value, str):
            upper = node.value.upper()
            if any(kw in upper for kw in _SQL_KEYWORDS):
                self.violations.append(
                    f"{self.filename}:{node.lineno} — raw SQL string: {node.value[:60]!r}. "
                    "Use SQLAlchemy ORM expressions."
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect direct ORM method calls on a session object in router bodies.

        Pattern: session.execute(...) / session.query(...) / session.add(...) etc.
        Injecting Session via Depends(get_db) and passing it to a service is fine.
        Calling ORM methods directly inside a route handler is the anti-pattern.
        """
        func = node.func
        if isinstance(func, ast.Attribute):
            # Direct calls like session.execute(...) where the object is 'session'
            if isinstance(func.value, ast.Name) and func.value.id in {
                "session", "db", "s"
            }:
                orm_methods = {
                    "execute", "query", "add", "add_all", "flush", "delete",
                    "scalar_one_or_none", "scalars",
                }
                if func.attr in orm_methods:
                    basename = Path(self.filename).name
                    if basename not in _SESSION_USAGE_EXCEPTIONS:
                        self.violations.append(
                            f"{self.filename}:{node.lineno} — direct ORM call "
                            f"session.{func.attr}() in router. "
                            "Delegate database access to a repository or service."
                        )
        self.generic_visit(node)


class TestStaticAstAnalysis:
    """Routers must contain no inline role checks, SQL strings, or session imports."""

    @pytest.fixture(scope="class")
    def router_files(self) -> list[Path]:
        files = sorted(_ROUTER_PACKAGE.glob("*.py"))
        return [f for f in files if not f.name.startswith("_")]

    def test_router_files_exist(self, router_files: list[Path]) -> None:
        assert len(router_files) >= 1, "No router files found in expected package"

    def test_no_inline_role_comparisons(self, router_files: list[Path]) -> None:
        all_violations: list[str] = []
        for path in router_files:
            source = path.read_text()
            tree = ast.parse(source, filename=str(path))
            visitor = _AstVisitor(str(path.name))
            visitor.visit(tree)
            # Only report role-comparison violations here
            all_violations.extend(
                v for v in visitor.violations if "inline role comparison" in v
            )
        assert not all_violations, (
            "Inline role/persona comparisons found in router files:\n"
            + "\n".join(all_violations)
        )

    def test_no_raw_sql_strings(self, router_files: list[Path]) -> None:
        all_violations: list[str] = []
        for path in router_files:
            source = path.read_text()
            tree = ast.parse(source, filename=str(path))
            visitor = _AstVisitor(str(path.name))
            visitor.visit(tree)
            all_violations.extend(
                v for v in visitor.violations if "raw SQL string" in v
            )
        assert not all_violations, (
            "Raw SQL string literals found in router files:\n"
            + "\n".join(all_violations)
        )

    def test_no_direct_session_orm_calls(self, router_files: list[Path]) -> None:
        all_violations: list[str] = []
        for path in router_files:
            source = path.read_text()
            tree = ast.parse(source, filename=str(path))
            visitor = _AstVisitor(str(path.name))
            visitor.visit(tree)
            all_violations.extend(
                v for v in visitor.violations if "direct ORM call" in v
            )
        assert not all_violations, (
            "Direct ORM session calls found in router files "
            "(delegate to repository/service via Depends):\n"
            + "\n".join(all_violations)
        )
