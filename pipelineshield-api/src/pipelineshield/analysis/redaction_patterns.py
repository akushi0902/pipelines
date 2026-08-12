"""Ordered, immutable registry of secret-detection patterns.

Each pattern entry carries:
  - pattern_id: stable identifier used in [REDACTED:<pattern_id>] tokens
  - regex: compiled regex with optional capture group
  - capture_group: 0 = whole match is secret; 1+ = that group is the secret span
  - description: human-readable summary for the catalogue doc

Patterns are applied in registry order; the first match on a span wins.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RedactionPattern:
    pattern_id: str
    regex: re.Pattern[str]
    capture_group: int
    description: str


# ---------------------------------------------------------------------------
# Individual pattern definitions
# ---------------------------------------------------------------------------

# 1. GitHub personal access tokens (classic: ghp_/gho_/ghs_/ghu_; fine-grained: github_pat_)
_GITHUB_PAT = RedactionPattern(
    pattern_id="github_pat",
    regex=re.compile(
        r"(?:github_pat_[A-Za-z0-9_]{22,255}|gh[posur]_[A-Za-z0-9]{36,255})",
        re.ASCII,
    ),
    capture_group=0,
    description=(
        "GitHub personal access token — classic (ghp_/gho_/ghs_/ghu_/ghr_) "
        "and fine-grained (github_pat_) token prefixes."
    ),
)

# 2. GitLab personal access tokens (glpat-)
_GITLAB_PAT = RedactionPattern(
    pattern_id="gitlab_pat",
    regex=re.compile(
        r"glpat-[A-Za-z0-9_\-]{20,255}",
        re.ASCII,
    ),
    capture_group=0,
    description=(
        "GitLab personal access token with glpat- prefix "
        "(20-255 alphanumeric/dash/underscore chars)."
    ),
)

# 3. AWS access key ID — starts with AKIA/ASIA/AROA/ANPA/ANVA/AIDA
_AWS_AK_ID = RedactionPattern(
    pattern_id="aws_access_key_id",
    regex=re.compile(
        r"(?<![A-Z0-9])(?:AKIA|ASIA|AROA|ANPA|ANVA|AIDA)[A-Z0-9]{16}(?![A-Z0-9])",
        re.ASCII,
    ),
    capture_group=0,
    description=(
        "AWS access key ID — 20-char uppercase token beginning with "
        "AKIA, ASIA, AROA, ANPA, ANVA, or AIDA."
    ),
)

# 4. JSON Web Token — three base64url segments, header typically starts with eyJ
_JWT = RedactionPattern(
    pattern_id="jwt",
    regex=re.compile(
        r"eyJ[A-Za-z0-9_\-]{4,4096}(?:\.[A-Za-z0-9_\-]{4,4096}){2}",
        re.ASCII,
    ),
    capture_group=0,
    description=(
        "JSON Web Token — three dot-separated base64url segments where "
        "the header begins with eyJ (base64url of '{')."
    ),
)

# 5. PEM-encoded private key / certificate block (multi-line)
_PEM_BLOCK = RedactionPattern(
    pattern_id="pem_block",
    regex=re.compile(
        r"-----BEGIN [A-Z ]{1,64}-----[\s\S]{1,65536}?-----END [A-Z ]{1,64}-----",
        re.MULTILINE,
    ),
    capture_group=0,
    description=(
        "PEM-encoded key or certificate block: -----BEGIN ...-----  through "
        "-----END ...-----  including all intervening lines."
    ),
)

# 6. Key-name value masker — YAML 'key: value' and shell 'KEY=value' shapes.
#    Capture group 1 is the VALUE span; the key itself is not masked.
#    Negative lookahead avoids re-masking already-masked tokens.
#    Using \w* (word chars only) avoids catastrophic backtracking on long lines.
_KEY_NAME_VALUE = RedactionPattern(
    pattern_id="key_name_value",
    regex=re.compile(
        r"(?im)"
        r"(?:^|(?<=\n))"                                  # line start
        r"[ \t]*"                                          # optional indent
        r"\w*(?:secret|token|password|passwd|pwd|credential|key)\w*"  # key with keyword
        r"[ \t]*[:=][ \t]*"                                # separator
        r"((?!\[REDACTED:)\S{1,4096})"                     # group 1: non-whitespace value
    ),
    capture_group=1,
    description=(
        "Any YAML-style 'key: value' or shell 'KEY=value' assignment where "
        "the key word contains secret, token, password, passwd, pwd, credential, "
        "or key (case-insensitive). Only the value span is masked."
    ),
)

# ---------------------------------------------------------------------------
# NOTE: High-entropy detection is NOT a RedactionPattern because it requires
# a post-regex entropy calculation.  It is handled separately in redactor.py.
# ---------------------------------------------------------------------------

# 7-entry ordered tuple — explicit patterns applied left-to-right.
# High-entropy runs after these in redactor.py.
ORDERED_PATTERNS: tuple[RedactionPattern, ...] = (
    _GITHUB_PAT,
    _GITLAB_PAT,
    _AWS_AK_ID,
    _JWT,
    _PEM_BLOCK,
    _KEY_NAME_VALUE,
)

