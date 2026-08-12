"""Unit tests for AuditRepository — append-only surface verification.

Verifies:
- AuditRepository interface exposes no update or delete methods
- SQLAlchemyAuditRepository exposes no update or delete methods
- Static test: no module outside AuditWriter imports AuditRepository.append
  or AuditEvent model directly (enforces the single-writer invariant for
  new code in this WO)
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest


class TestAuditRepositorySurface:
    def test_abstract_interface_has_no_update_method(self) -> None:
        from pipelineshield.persistence.repositories.audit import AuditRepository

        public_methods = {
            name
            for name, _ in inspect.getmembers(AuditRepository, predicate=inspect.isfunction)
            if not name.startswith("_")
        }
        assert "update" not in public_methods, "AuditRepository must not expose update()"
        assert "delete" not in public_methods, "AuditRepository must not expose delete()"
        assert "remove" not in public_methods
        assert "save" not in public_methods

    def test_sqlalchemy_impl_has_no_update_method(self) -> None:
        from pipelineshield.persistence.repositories.audit import SQLAlchemyAuditRepository

        public_methods = {
            name
            for name, _ in inspect.getmembers(SQLAlchemyAuditRepository, predicate=inspect.isfunction)
            if not name.startswith("_")
        }
        assert "update" not in public_methods
        assert "delete" not in public_methods

    def test_append_is_only_write_method(self) -> None:
        from pipelineshield.persistence.repositories.audit import AuditRepository

        public_methods = {
            name
            for name, _ in inspect.getmembers(AuditRepository, predicate=inspect.isfunction)
            if not name.startswith("_")
        }
        write_methods = {m for m in public_methods if "append" in m or "write" in m or "insert" in m or "create" in m or "add" in m}
        assert write_methods == {"append"}, f"Expected only 'append' as write method, got: {write_methods}"

    def test_audit_writer_is_single_import_point_for_writes(self) -> None:
        """Static test: only audit_writer.py should import SQLAlchemyAuditRepository
        for writing purposes.  audit_router.py may import it for reads.

        Scans all source files to assert no other module adds SQLAlchemyAuditRepository
        as a write path outside of the designated single-writer.
        """
        src_root = Path(__file__).parent.parent.parent / "src" / "pipelineshield"
        # Permitted importers: the writer and the read-only router
        _ALLOWED = {"audit_writer", "audit_router", "audit.py"}
        violations = []

        for py_file in src_root.rglob("*.py"):
            rel = py_file.relative_to(src_root)
            rel_str = str(rel)
            if any(allowed in rel_str for allowed in _ALLOWED):
                continue
            if rel_str == "persistence/repositories/audit.py":
                continue
            content = py_file.read_text(encoding="utf-8")
            if "SQLAlchemyAuditRepository" in content:
                lines = [
                    line.strip()
                    for line in content.splitlines()
                    if "SQLAlchemyAuditRepository" in line and "import" in line
                ]
                if lines:
                    violations.append(f"{rel}: {lines}")

        assert not violations, (
            "SQLAlchemyAuditRepository must only be imported in audit_writer.py "
            f"and audit_router.py. Found unexpected imports: {violations}"
        )


class TestAuditWriterSinglePath:
    def test_audit_writer_uses_content_guard(self) -> None:
        import inspect
        from pipelineshield.platform import audit_writer

        source = inspect.getsource(audit_writer)
        assert "guard_change_detail" in source, "AuditWriter must call content guard"
        assert "AuditContentViolation" in source

    def test_audit_writer_write_method_exists(self) -> None:
        from pipelineshield.platform.audit_writer import AuditWriter

        assert hasattr(AuditWriter, "write")
        assert callable(AuditWriter.write)

    def test_new_platform_modules_use_audit_writer(self) -> None:
        """New platform modules introduced in WO-038 should use AuditWriter.

        Note: auth_module.py (from WO-036) imports AuditEvent directly as it
        predates AuditWriter — this is a known exception tracked for future
        refactoring.  Only audit_writer.py and auth_module.py (legacy) are
        permitted to import AuditEvent directly within the platform package.
        """
        platform_root = (
            Path(__file__).parent.parent.parent
            / "src" / "pipelineshield" / "platform"
        )
        # These are the only permitted direct importers
        _PERMITTED = {"audit_writer.py", "auth_module.py"}
        violations = []
        for py_file in platform_root.rglob("*.py"):
            if py_file.name in _PERMITTED:
                continue
            content = py_file.read_text(encoding="utf-8")
            if "from pipelineshield.persistence.models.audit_event import" in content:
                violations.append(py_file.name)
        assert not violations, (
            f"Unexpected direct AuditEvent imports in platform (use AuditWriter): {violations}"
        )
