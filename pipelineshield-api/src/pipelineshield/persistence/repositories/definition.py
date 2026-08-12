"""DefinitionRepository — abstract interface and SQLAlchemy implementation.

Handles encrypted pipeline definitions.  The KeyProvider is injected so that
the repository never holds or derives encryption keys directly.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.pipeline_definition import PipelineDefinition
from ...crypto.key_provider import KeyProvider


class DefinitionRepository(ABC):
    """Abstract repository interface for PipelineDefinition entities.

    The repository decrypts masked_content transparently via the KeyProvider
    so callers receive plaintext and never interact with ciphertext directly.
    """

    @abstractmethod
    def get_by_analysis(
        self, analysis_id: uuid.UUID, workspace_id: uuid.UUID
    ) -> PipelineDefinition | None:
        """Return the definition for *analysis_id* within *workspace_id*."""

    @abstractmethod
    def get_plaintext(
        self, analysis_id: uuid.UUID, workspace_id: uuid.UUID
    ) -> str | None:
        """Return decrypted definition content, or None if not found."""

    @abstractmethod
    def add_encrypted(
        self,
        definition: PipelineDefinition,
        plaintext_content: str,
    ) -> PipelineDefinition:
        """Encrypt *plaintext_content*, store it in *definition.masked_content*,
        and persist the row.  Returns the managed instance."""

    @abstractmethod
    def delete(self, definition: PipelineDefinition) -> None:
        """Hard-delete *definition*.  No soft-delete path exists."""


class SQLAlchemyDefinitionRepository(DefinitionRepository):
    """SQLAlchemy 2.0 implementation of DefinitionRepository."""

    def __init__(self, session: Session, key_provider: KeyProvider) -> None:
        self._session = session
        self._key_provider = key_provider

    def get_by_analysis(
        self, analysis_id: uuid.UUID, workspace_id: uuid.UUID
    ) -> PipelineDefinition | None:
        stmt = select(PipelineDefinition).where(
            PipelineDefinition.analysis_id == analysis_id,
            PipelineDefinition.workspace_id == workspace_id,
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def get_plaintext(
        self, analysis_id: uuid.UUID, workspace_id: uuid.UUID
    ) -> str | None:
        defn = self.get_by_analysis(analysis_id, workspace_id)
        if defn is None:
            return None
        return self._key_provider.decrypt(defn.masked_content)

    def add_encrypted(
        self,
        definition: PipelineDefinition,
        plaintext_content: str,
    ) -> PipelineDefinition:
        definition.masked_content = self._key_provider.encrypt(plaintext_content)
        definition.key_id = self._key_provider.key_id
        # Set purge_due_at to 90 days from now unless already set by the caller.
        if definition.purge_due_at is None:
            definition.purge_due_at = datetime.now(tz=timezone.utc) + timedelta(days=90)
        # Samples are never purged; override retention_class accordingly.
        if definition.is_sample:
            definition.retention_class = "sample"
        self._session.add(definition)
        self._session.flush()
        return definition

    def delete(self, definition: PipelineDefinition) -> None:
        self._session.delete(definition)
        self._session.flush()
