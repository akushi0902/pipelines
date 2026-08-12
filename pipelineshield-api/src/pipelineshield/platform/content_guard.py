"""Content guard for audit change_detail payloads.

The content guard runs in REJECT mode (not mask mode): if a change_detail
document contains secret-shaped values or pipeline definition content,
the guard raises AuditContentViolation so the calling operation fails fast
rather than persisting Confidential material in the audit trail.

Pattern set reused from the ingestion redactor:
  - GitHub / GitLab PAT patterns
  - AWS access key ID
  - JWT (three base64url parts separated by dots)
  - PEM block (BEGIN … header)
  - High-entropy token (>= 32 chars, Shannon entropy >= 4.5 bits/char)
  - Secret-like key names (password, secret, token, key, credential, …)

Size guard: change_detail dicts exceeding MAX_BYTES are truncated and
marked with {"_truncated": true} so the event is never silently lost.
"""
from __future__ import annotations

import json
import logging
import math
import re
from typing import Any

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_BYTES: int = 65_536  # 64 KB — bounded structured document limit

# ---------------------------------------------------------------------------
# Reject-mode patterns (subset of ingestion redactor pattern set)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # GitHub fine-grained or classic PAT
    ("github_pat", re.compile(r"(?:ghp|github_pat|gho|ghs|ghr)_[A-Za-z0-9]{36,255}", re.I)),
    # GitLab PAT
    ("gitlab_pat", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}", re.I)),
    # AWS access key ID
    ("aws_access_key_id", re.compile(r"(?<![A-Z0-9])(?:AKIA|AIPA|AIAA|AIDA|AROA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    # JWT — three base64url segments separated by dots
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    # PEM block header
    ("pem_block", re.compile(r"-----BEGIN [A-Z ]+-----", re.M)),
    # Secret-like key=value pairs in string values
    ("key_name_value", re.compile(
        r'\b\w*(?:secret|token|password|passwd|pwd|credential|key)\w*\s*[:=]\s*(?!\[REDACTED:)\S{8,}',
        re.I,
    )),
]

# High-entropy detection
_ENTROPY_THRESHOLD: float = 4.5
_ENTROPY_MIN_LEN: int = 32
_ENTROPY_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,1024}")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AuditContentViolation(Exception):
    """Raised when change_detail contains secret-shaped or Confidential content.

    The violating field name is recorded; the violating VALUE is never logged
    or included in the exception message.
    """

    def __init__(self, field_path: str, pattern_id: str) -> None:
        super().__init__(
            f"change_detail field '{field_path}' contains content matching "
            f"pattern '{pattern_id}'; the value must not appear in audit records."
        )
        self.field_path = field_path
        self.pattern_id = pattern_id


# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _has_high_entropy_token(value: str) -> bool:
    for match in _ENTROPY_CANDIDATE_RE.finditer(value):
        if _shannon_entropy(match.group()) >= _ENTROPY_THRESHOLD:
            return True
    return False


# ---------------------------------------------------------------------------
# Recursive field scanner
# ---------------------------------------------------------------------------


def _scan_value(value: Any, path: str) -> None:
    """Recursively scan a value for secret-shaped content.

    Raises AuditContentViolation with the field path if a violation is found.
    The violating value itself is never included in the error or log output.
    """
    if isinstance(value, str):
        for pattern_id, pattern in _SECRET_PATTERNS:
            if pattern.search(value):
                _LOG.warning(
                    "audit_content_guard_reject",
                    extra={"field_path": path, "pattern_id": pattern_id},
                )
                raise AuditContentViolation(path, pattern_id)
        if len(value) >= _ENTROPY_MIN_LEN and _has_high_entropy_token(value):
            _LOG.warning(
                "audit_content_guard_reject",
                extra={"field_path": path, "pattern_id": "high_entropy"},
            )
            raise AuditContentViolation(path, "high_entropy")
    elif isinstance(value, dict):
        for k, v in value.items():
            _scan_value(v, f"{path}.{k}" if path else k)
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _scan_value(item, f"{path}[{i}]")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def guard_change_detail(change_detail: dict[str, Any]) -> dict[str, Any]:
    """Validate and size-cap change_detail.

    Returns the (possibly truncated) change_detail dict.
    Raises AuditContentViolation if the payload contains secret-shaped values.
    """
    # 1. Secret / Confidential content check
    _scan_value(change_detail, "")

    # 2. Size guard — truncate rather than reject so events are never lost
    try:
        serialized = json.dumps(change_detail, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        serialized = "{}"
        change_detail = {}

    if len(serialized.encode()) > MAX_BYTES:
        _LOG.info(
            "audit_change_detail_truncated",
            extra={"original_bytes": len(serialized.encode())},
        )
        return {"_truncated": True, "_reason": "change_detail exceeded max size"}

    return change_detail
