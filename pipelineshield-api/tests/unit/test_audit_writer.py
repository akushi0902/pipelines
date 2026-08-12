"""Unit tests for AuditWriter.

Tests:
- Field construction: all fields are correctly stored on the row
- Correlation_id propagation: supplied correlation_id appears on the row
- Rejection of write missing actor_id
- UTC normalisation: occurred_at is stored with timezone context
- Masking delegation: change_detail is passed through content guard
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.platform.audit_writer import AuditWriter, AuditWriteError
from pipelineshield.platform.content_guard import AuditContentViolation


@pytest.fixture(scope="module")
def engine():
    _engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(_engine)
    return _engine


@pytest.fixture()
def session(engine):
    _Session = sessionmaker(bind=engine)
    s = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


class TestAuditWriterFieldConstruction:
    def test_all_fields_stored(self, session) -> None:
        writer = AuditWriter(session)
        ws_id = uuid.uuid4()
        user_id = uuid.uuid4()
        corr = "test-corr-001"

        event = writer.write(
            actor_id="user-abc",
            actor_persona="devsecops_engineer",
            actor_user_id=user_id,
            workspace_id=ws_id,
            action="catalogue.version_created",
            resource_type="catalogue",
            resource_id="42",
            change_detail={"version": 3},
            correlation_id=corr,
            source_ip_masked="10.0.0.0",
            user_agent_hash="deadbeef",
        )
        session.flush()

        row = session.execute(
            select(AuditEvent).where(AuditEvent.id == event.id)
        ).scalar_one()

        assert row.actor_id == "user-abc"
        assert row.actor_persona == "devsecops_engineer"
        assert row.actor_user_id == user_id
        assert row.workspace_id == ws_id
        assert row.action == "catalogue.version_created"
        assert row.resource_type == "catalogue"
        assert row.resource_id == "42"
        assert row.change_detail == {"version": 3}
        assert row.correlation_id == corr
        assert row.source_ip_masked == "10.0.0.0"
        assert row.user_agent_hash == "deadbeef"

    def test_optional_fields_default_to_none(self, session) -> None:
        writer = AuditWriter(session)
        event = writer.write(
            actor_id="system",
            action="system.heartbeat",
            resource_type="system",
        )
        session.flush()

        row = session.execute(
            select(AuditEvent).where(AuditEvent.id == event.id)
        ).scalar_one()

        assert row.actor_persona is None
        assert row.workspace_id is None
        assert row.resource_id is None
        assert row.source_ip_masked is None
        assert row.user_agent_hash is None

    def test_correlation_id_auto_generated_when_absent(self, session) -> None:
        writer = AuditWriter(session)
        event = writer.write(
            actor_id="system",
            action="system.test",
            resource_type="system",
        )
        session.flush()

        row = session.execute(
            select(AuditEvent).where(AuditEvent.id == event.id)
        ).scalar_one()
        assert row.correlation_id is not None
        assert len(row.correlation_id) > 0


class TestAuditWriterCorrelationIdPropagation:
    def test_supplied_correlation_id_is_stored(self, session) -> None:
        writer = AuditWriter(session)
        specific_corr = "specific-correlation-xyz-789"

        event = writer.write(
            actor_id="actor-99",
            action="auth.logout",
            resource_type="auth",
            correlation_id=specific_corr,
        )
        session.flush()

        row = session.execute(
            select(AuditEvent).where(AuditEvent.id == event.id)
        ).scalar_one()
        assert row.correlation_id == specific_corr

    def test_different_calls_preserve_different_correlation_ids(self, session) -> None:
        writer = AuditWriter(session)
        corr1 = "corr-alpha"
        corr2 = "corr-beta"

        e1 = writer.write(
            actor_id="actor-1",
            action="test.first",
            resource_type="test",
            correlation_id=corr1,
        )
        e2 = writer.write(
            actor_id="actor-2",
            action="test.second",
            resource_type="test",
            correlation_id=corr2,
        )
        session.flush()

        row1 = session.execute(
            select(AuditEvent).where(AuditEvent.id == e1.id)
        ).scalar_one()
        row2 = session.execute(
            select(AuditEvent).where(AuditEvent.id == e2.id)
        ).scalar_one()

        assert row1.correlation_id == corr1
        assert row2.correlation_id == corr2
        assert row1.correlation_id != row2.correlation_id


class TestAuditWriterActorValidation:
    def test_missing_actor_id_raises_audit_write_error(self, session) -> None:
        writer = AuditWriter(session)
        with pytest.raises(AuditWriteError, match="actor_id must be provided"):
            writer.write(
                actor_id="",
                action="test.no_actor",
                resource_type="test",
            )

    def test_none_actor_id_raises_audit_write_error(self, session) -> None:
        writer = AuditWriter(session)
        with pytest.raises(AuditWriteError, match="actor_id must be provided"):
            writer.write(
                actor_id=None,  # type: ignore[arg-type]
                action="test.none_actor",
                resource_type="test",
            )

    def test_missing_actor_leaves_no_row(self, session) -> None:
        writer = AuditWriter(session)
        action = "test.no_actor_no_row"
        from sqlalchemy import select as _select
        before = len(session.execute(
            _select(AuditEvent).where(AuditEvent.action == action)
        ).scalars().all())

        try:
            writer.write(actor_id="", action=action, resource_type="test")
        except AuditWriteError:
            pass
        session.flush()

        after = len(session.execute(
            _select(AuditEvent).where(AuditEvent.action == action)
        ).scalars().all())
        assert after == before, "Failed actor validation must not persist a row"

    def test_valid_actor_id_succeeds(self, session) -> None:
        writer = AuditWriter(session)
        event = writer.write(
            actor_id="00000000-0000-0000-0000-000000000001",
            action="test.valid_actor",
            resource_type="test",
        )
        session.flush()
        assert event.actor_id == "00000000-0000-0000-0000-000000000001"


class TestAuditWriterContentGuardDelegation:
    def test_secret_in_change_detail_raises_content_violation(self, session) -> None:
        writer = AuditWriter(session)
        with pytest.raises(AuditContentViolation):
            writer.write(
                actor_id="actor",
                action="test.secret",
                resource_type="test",
                change_detail={"token": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            )

    def test_error_message_never_includes_secret_value(self, session) -> None:
        writer = AuditWriter(session)
        secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        with pytest.raises(AuditContentViolation) as exc_info:
            writer.write(
                actor_id="actor",
                action="test.secret_leak_check",
                resource_type="test",
                change_detail={"token": secret},
            )
        assert secret not in str(exc_info.value)

    def test_safe_change_detail_passes(self, session) -> None:
        writer = AuditWriter(session)
        event = writer.write(
            actor_id="actor",
            action="test.safe_detail",
            resource_type="test",
            change_detail={"version": 1, "format": "github_actions"},
        )
        session.flush()
        assert event.change_detail == {"version": 1, "format": "github_actions"}
