"""Framework-free analysis core for PipelineShield.

This package must never import FastAPI, SQLAlchemy, or any HTTP/database module.
"""
from .redactor import RedactedDoc, RedactionTimeoutError, redact
from .redaction_patterns import ORDERED_PATTERNS, RedactionPattern

__all__ = [
    "redact",
    "RedactedDoc",
    "RedactionTimeoutError",
    "ORDERED_PATTERNS",
    "RedactionPattern",
]
