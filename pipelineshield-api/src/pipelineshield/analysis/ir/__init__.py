"""Versioned PipelineIR contract.

This package must never import FastAPI, SQLAlchemy, or any HTTP/database module.
Rules must access the IR through accessors.py, never raw dict keys.
"""
from .pipeline_ir import (
    IR_VERSION,
    ActionRef,
    Anchor,
    CoverageReport,
    EffectivePermissions,
    Job,
    PipelineIR,
    SecretRef,
    Step,
    UnresolvedFragment,
)

__all__ = [
    "IR_VERSION",
    "Anchor",
    "ActionRef",
    "CoverageReport",
    "EffectivePermissions",
    "Job",
    "PipelineIR",
    "SecretRef",
    "Step",
    "UnresolvedFragment",
]
