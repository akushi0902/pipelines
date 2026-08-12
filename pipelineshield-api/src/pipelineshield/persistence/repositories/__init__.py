"""Repository interfaces and SQLAlchemy implementations.

Later stories inject repositories rather than opening sessions directly,
keeping SQL dialect concerns in a single layer and enabling test doubles.
"""
from .analysis import AnalysisRepository, SQLAlchemyAnalysisRepository
from .definition import DefinitionRepository, SQLAlchemyDefinitionRepository
from .finding import FindingRepository, SQLAlchemyFindingRepository
from .catalogue import CatalogueRepository, SQLAlchemyCatalogueRepository
from .audit import AuditRepository, SQLAlchemyAuditRepository

__all__ = [
    "AnalysisRepository",
    "SQLAlchemyAnalysisRepository",
    "DefinitionRepository",
    "SQLAlchemyDefinitionRepository",
    "FindingRepository",
    "SQLAlchemyFindingRepository",
    "CatalogueRepository",
    "SQLAlchemyCatalogueRepository",
    "AuditRepository",
    "SQLAlchemyAuditRepository",
]
