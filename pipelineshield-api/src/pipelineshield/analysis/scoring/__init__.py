"""Deterministic weighted scoring engine for PipelineShield (WO-020).

No FastAPI, SQLAlchemy, or HTTP-client imports are permitted in this package.
"""
from .engine import ScoringEngine
from .models import (
    CategoryScore,
    ControlVerdict,
    ScoreResult,
    ScoringError,
    VerdictEnum,
)

__all__ = [
    "CategoryScore",
    "ControlVerdict",
    "ScoreResult",
    "ScoringEngine",
    "ScoringError",
    "VerdictEnum",
]
