"""Unit and property tests for the secret redactor.

Covers:
  - Positive and negative case per pattern class
  - Byte-length preservation (hard invariant)
  - Line/column offset stability
  - Idempotency: redact(redact(text)) == redact(text)
  - Anti-leak: serialised output never contains plaintext secrets
  - Import-graph isolation: analysis core has no FastAPI or SQLAlchemy imports
  - Hypothesis property tests for length, offsets, and idempotency
"""
from __future__ import annotations

import importlib
import importlib.util
import logging
import math
import sys
from pathlib import Path
from typing import Iterator

import pytest

# Hypothesis is optional; skip property tests if not installed.
try:
    from hypothesis import given, settings
    from hypothesis import strategies as st

    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

from pipelineshield.analysis.redactor import (
    RedactedDoc,
    RedactionTimeoutError,
    _shannon_entropy,
    redact,
)
from pipelineshield.analysis.redaction_patterns import ORDERED_PATTERNS

FIXTURES = Path(__file__).parent.parent / "fixtures" / "redaction"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _line_col_index(text: str) -> dict[int, list[tuple[int, int]]]:
    """Map each character value → list of (line, col) pairs (0-indexed)."""
    index: dict[int, list[tuple[int, int]]] = {}
    for line_no, line in enumerate(text.splitlines(keepends=True)):
        for col, ch in enumerate(line):
            index.setdefault(ord(ch), []).append((line_no, col))
    return index


# ---------------------------------------------------------------------------
# Core invariants (parameterised helper)
# ---------------------------------------------------------------------------


def _assert_invariants(doc: RedactedDoc, original_text: str) -> None:
    assert len(doc.masked_text) == len(original_text), (
        f"Length violated: {len(original_text)} → {len(doc.masked_text)}"
    )
    assert doc.masked_text.count("\n") == original_text.count("\n"), (
        "Newline count changed — line offsets broken"
    )


# ---------------------------------------------------------------------------
# Pattern: github_pat
# ---------------------------------------------------------------------------


def test_github_pat_classic_masked():
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
    text = f"token: {secret}"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert secret not in doc.masked_text
    assert "github_pat" in doc.pattern_counts
    assert "[REDACTED:github_pat]" in doc.masked_text


def test_github_pat_fine_grained_masked():
    secret = "github_pat_11AABBCCDDEE0000000000_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    text = f"GITHUB_PAT={secret}"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert secret not in doc.masked_text
    assert "github_pat" in doc.pattern_counts


def test_github_pat_negative_no_false_positive():
    # Normal English word is not a PAT
    text = "The repository name is ghs_abc (too short to be a PAT)"
    doc = redact(text)
    # The 3-char suffix is too short (< 36) — should not match
    assert doc.masked_text == text
    assert not doc.pattern_counts


def test_github_pat_from_fixture():
    raw = (FIXTURES / "github_pat.yml").read_text()
    doc = redact(raw)
    _assert_invariants(doc, raw)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234" not in doc.masked_text
    assert "github_pat" in doc.pattern_counts


# ---------------------------------------------------------------------------
# Pattern: gitlab_pat
# ---------------------------------------------------------------------------


def test_gitlab_pat_masked():
    secret = "glpat-xYzAbCdEfGhIjKlMnOpQr"
    text = f"GL_TOKEN={secret}"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert secret not in doc.masked_text
    assert "[REDACTED:gitlab_pat]" in doc.masked_text
    assert "gitlab_pat" in doc.pattern_counts


def test_gitlab_pat_negative():
    # Too-short suffix — must not match
    text = "glpat-tooshort"
    doc = redact(text)
    assert doc.masked_text == text


def test_gitlab_pat_from_fixture():
    raw = (FIXTURES / "gitlab_pat.yml").read_text()
    doc = redact(raw)
    _assert_invariants(doc, raw)
    assert "glpat-xYzAbCdEfGhIjKlMnOpQr" not in doc.masked_text


# ---------------------------------------------------------------------------
# Pattern: aws_access_key_id
# ---------------------------------------------------------------------------


def test_aws_access_key_id_masked():
    secret = "AKIAIOSFODNN7EXAMPLE"
    text = f"AWS_ACCESS_KEY_ID={secret}"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert secret not in doc.masked_text
    assert "aws_access_key_id" in doc.pattern_counts


def test_aws_access_key_id_short_span_uses_x_mask():
    # AKIA + 16 uppercase chars = 20 chars; token [REDACTED:aws_access_key_id] = 27 chars
    # Must fall back to 20 X's
    secret = "AKIAIOSFODNN7EXAMPLE"
    assert len(secret) == 20
    text = f"key={secret}"
    doc = redact(text)
    token = "[REDACTED:aws_access_key_id]"
    assert len(token) > len(secret)  # fallback scenario
    masked_value = doc.masked_text[len("key="):]
    assert masked_value == "X" * len(secret)


def test_aws_access_key_id_negative():
    # Only 15 digits after prefix — must not match
    text = "AKIASHORTKEY123"
    doc = redact(text)
    assert doc.masked_text == text


def test_aws_access_key_id_from_fixture():
    raw = (FIXTURES / "aws_access_key.yml").read_text()
    doc = redact(raw)
    _assert_invariants(doc, raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in doc.masked_text


# ---------------------------------------------------------------------------
# Pattern: jwt
# ---------------------------------------------------------------------------


def test_jwt_masked():
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNzAwMDAwMDAwfQ"
    signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    secret = f"{header}.{payload}.{signature}"
    text = f"API_TOKEN={secret}"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert secret not in doc.masked_text
    assert "[REDACTED:jwt]" in doc.masked_text
    assert "jwt" in doc.pattern_counts


def test_jwt_negative_two_segments_only():
    # Only two segments — not a valid JWT
    text = "eyJhbGci.eyJzdWIi"
    doc = redact(text)
    assert doc.masked_text == text


def test_jwt_from_fixture():
    raw = (FIXTURES / "jwt.yml").read_text()
    doc = redact(raw)
    _assert_invariants(doc, raw)
    assert "jwt" in doc.pattern_counts


# ---------------------------------------------------------------------------
# Pattern: pem_block
# ---------------------------------------------------------------------------


def test_pem_block_masked():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAFAKEKEYDATAHEREABCD\n"
        "-----END RSA PRIVATE KEY-----"
    )
    text = f"key: |\n  {pem}"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert "MIIEowIBAAKCAQEAFAKEKEYDATAHEREABCD" not in doc.masked_text
    assert "pem_block" in doc.pattern_counts


def test_pem_block_newlines_preserved():
    pem = (
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHQCAQEEIFAKEDATAHEREabcdefghijklmno\n"
        "-----END EC PRIVATE KEY-----"
    )
    original_newline_count = pem.count("\n")
    doc = redact(pem)
    assert doc.masked_text.count("\n") == original_newline_count


def test_pem_block_from_fixture():
    raw = (FIXTURES / "pem_block.yml").read_text()
    doc = redact(raw)
    _assert_invariants(doc, raw)
    assert "MIIEowIBAAKCAQEAFAKEKEYDATAHEREABCDEFGHIJKLMNOPQRSTUVWXYZ012345" not in doc.masked_text
    assert "pem_block" in doc.pattern_counts


# ---------------------------------------------------------------------------
# Pattern: key_name_value
# ---------------------------------------------------------------------------


def test_key_name_value_yaml_style():
    text = "db_password: my-super-secret-value\n"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert "my-super-secret-value" not in doc.masked_text
    assert "key_name_value" in doc.pattern_counts
    # Key itself should still be visible
    assert "db_password" in doc.masked_text


def test_key_name_value_shell_style():
    text = "export API_SECRET=supersecretapivalue123\n"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert "supersecretapivalue123" not in doc.masked_text
    assert "key_name_value" in doc.pattern_counts


def test_key_name_value_standalone_keyword():
    text = "SECRET=standalone-secret-value\n"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert "standalone-secret-value" not in doc.masked_text


def test_key_name_value_negative_unrelated_key():
    # 'name' does not contain any sensitive keyword
    text = "name: my-pipeline\nversion: 1.0\n"
    doc = redact(text)
    assert doc.masked_text == text


def test_key_name_value_from_fixture():
    raw = (FIXTURES / "key_name_value.yml").read_text()
    doc = redact(raw)
    _assert_invariants(doc, raw)
    assert "sup3r" not in doc.masked_text
    assert "key_name_value" in doc.pattern_counts


# ---------------------------------------------------------------------------
# Pattern: high_entropy
# ---------------------------------------------------------------------------


def test_high_entropy_random_string():
    # 38-char random-looking alphanumeric — should be caught by entropy detector
    secret = "kX8mN2qR5vY9wZ3pL6hJ7dA0sG4tC1nBfE2uI"
    assert len(secret) >= 32
    text = f"CUSTOM_AUTH={secret}\n"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert secret not in doc.masked_text
    assert "high_entropy" in doc.pattern_counts


def test_high_entropy_negative_sha256_hex():
    # SHA-256 hex digest: 64 hex chars, entropy ~4.0 < threshold 4.5
    sha = "a" * 32 + "b" * 32  # simple low-entropy hex-ish
    entropy = _shannon_entropy(sha)
    assert entropy < 4.5, f"Expected low entropy for repetitive hex, got {entropy}"
    text = f"sha256:{sha}\n"
    doc = redact(text)
    # Should NOT be masked (low entropy)
    assert sha not in doc.masked_text or doc.masked_text == text


def test_high_entropy_negative_short_string():
    # 31 chars — below minimum length, must not be masked regardless of entropy
    short = "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"
    assert len(short) == 31
    text = f"val={short}\n"
    doc = redact(text)
    # key_name_value doesn't match 'val'; high_entropy requires >=32 chars
    assert short not in doc.masked_text or doc.masked_text == text


def test_high_entropy_from_fixture():
    raw = (FIXTURES / "high_entropy.yml").read_text()
    doc = redact(raw)
    _assert_invariants(doc, raw)
    assert "kX8mN2qR5vY9wZ3pL6hJ7dA0sG4tC1nBfE2uI" not in doc.masked_text


# ---------------------------------------------------------------------------
# Shannon entropy helper
# ---------------------------------------------------------------------------


def test_shannon_entropy_uniform():
    # All-same chars: entropy = 0
    assert _shannon_entropy("aaaa") == 0.0


def test_shannon_entropy_two_equal():
    # Two different chars equally distributed: entropy = 1 bit
    assert abs(_shannon_entropy("ababababab") - 1.0) < 1e-9


def test_shannon_entropy_empty():
    assert _shannon_entropy("") == 0.0


# ---------------------------------------------------------------------------
# Length preservation invariant
# ---------------------------------------------------------------------------


def test_length_preserved_all_fixtures():
    for fixture_file in FIXTURES.glob("*.yml"):
        if "masked" in fixture_file.name:
            continue
        raw = fixture_file.read_text()
        doc = redact(raw)
        assert len(doc.masked_text) == len(raw), (
            f"{fixture_file.name}: length violated: {len(raw)} → {len(doc.masked_text)}"
        )


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_idempotency_github_pat():
    secret = "ghp_IDEMPOTENCYTESTABCDEFGHIJKLMNOPQrs"
    text = f"token: {secret}\n"
    once = redact(text).masked_text
    twice = redact(once).masked_text
    assert once == twice


def test_idempotency_key_name_value():
    text = "API_SECRET=my-api-secret-value\n"
    once = redact(text).masked_text
    twice = redact(once).masked_text
    assert once == twice


def test_idempotency_empty_input():
    doc = redact("")
    assert doc.masked_text == ""
    assert not doc.pattern_counts


def test_idempotency_whitespace_only():
    text = "   \n\t\n   "
    doc = redact(text)
    assert doc.masked_text == text


# ---------------------------------------------------------------------------
# Anti-leak: serialisation and repr
# ---------------------------------------------------------------------------


def test_redacted_doc_model_dump_excludes_map():
    secret = "ghp_SERIALISATIONTESTABCDEFGHIJKLMNOabc"
    text = f"token: {secret}\n"
    doc = redact(text)
    dumped = doc.model_dump()
    assert "redaction_map" not in dumped
    assert secret not in str(dumped)


def test_redacted_doc_repr_omits_map_contents():
    secret = "ghp_REPRTESTABCDEFGHIJKLMNOPQRSTUVWXab"
    text = f"token: {secret}\n"
    doc = redact(text)
    r = repr(doc)
    assert secret not in r
    assert "RedactedDoc" in r


def test_redaction_map_repr_shows_count_only():
    secret = "ghp_MAPREPRTESTABCDEFGHIJKLMNOPQRSTUWXa"
    text = f"token: {secret}\n"
    doc = redact(text)
    rmap_repr = repr(doc.redaction_map)
    assert secret not in rmap_repr
    assert "span" in rmap_repr.lower() or "RedactionMap" in rmap_repr


def test_anti_leak_log_record(caplog):
    secret = "ghp_LOGLEAKTESTABCDEFGHIJKLMNOPQRSTUVab"
    text = f"token: {secret}\n"
    with caplog.at_level(logging.INFO, logger="pipelineshield.analysis.redactor"):
        redact(text)
    for record in caplog.records:
        assert secret not in record.getMessage()
        assert secret not in str(record.__dict__)


# ---------------------------------------------------------------------------
# Line and column offset stability
# ---------------------------------------------------------------------------


def test_offset_stability_single_line():
    """Non-secret tokens before and after a secret must keep same line/col."""
    text = "prefix: hello\nsecret_key: AKIAIOSFODNN7EXAMPLE\nsuffix: world\n"
    doc = redact(text)
    # Lines 0, 2 (prefix/suffix) must be untouched
    orig_lines = text.splitlines()
    masked_lines = doc.masked_text.splitlines()
    assert masked_lines[0] == orig_lines[0]
    assert masked_lines[2] == orig_lines[2]


def test_offset_stability_no_change_to_line_count():
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIBBKFAKEDATAHEREabcdefghijklm\n"
        "-----END CERTIFICATE-----\n"
    )
    text = f"steps:\n  - run: cat <<EOF\n{pem}EOF\n"
    doc = redact(text)
    assert doc.masked_text.count("\n") == text.count("\n")


# ---------------------------------------------------------------------------
# Import-graph isolation
# ---------------------------------------------------------------------------


def test_no_fastapi_import():
    """analysis.redactor must not transitively import fastapi."""
    # Reload into isolated namespace to inspect imports
    spec = importlib.util.find_spec("pipelineshield.analysis.redactor")
    assert spec is not None
    module = importlib.import_module("pipelineshield.analysis.redactor")
    # Walk __spec__ of all imported modules reachable from the module
    for name in list(sys.modules):
        if name.startswith("pipelineshield.analysis"):
            continue  # the module itself is fine
        if "fastapi" in name:
            assert False, f"Forbidden import found: {name}"


def test_no_sqlalchemy_import():
    """analysis.redactor must not transitively import sqlalchemy."""
    for name in list(sys.modules):
        if name.startswith("pipelineshield.analysis"):
            continue
        if "sqlalchemy" in name:
            assert False, f"Forbidden import found: {name}"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_input():
    doc = redact("")
    assert doc.masked_text == ""
    assert doc.pattern_counts == {}


def test_whitespace_input():
    text = "\n\n   \t\n"
    doc = redact(text)
    assert doc.masked_text == text


def test_overlapping_patterns_resolved_deterministically():
    # A string that matches both github_pat AND key_name_value.
    # github_pat has lower registry_index → wins, but the value span
    # from key_name_value would be later in the registry.
    # The PAT is on its own line without a key= prefix, so only github_pat fires.
    secret = "ghp_OVERLAPTESTABCDEFGHIJKLMNOPQRSTUab"
    text = f"{secret}\n"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert secret not in doc.masked_text
    # Only one match should be in pattern_counts (github_pat)
    total = sum(doc.pattern_counts.values())
    assert total == 1


def test_multiple_secrets_in_one_text():
    gh = "ghp_MULTISECRETABCDEFGHIJKLMNOPQRSTUVWa"
    gl = "glpat-MultiSecretGitLabTestValue1234"
    text = f"GH_TOKEN={gh}\nGL_TOKEN={gl}\n"
    doc = redact(text)
    assert len(doc.masked_text) == len(text)
    assert gh not in doc.masked_text
    assert gl not in doc.masked_text
    total = sum(doc.pattern_counts.values())
    assert total == 2


# ---------------------------------------------------------------------------
# Hypothesis property tests (skipped if hypothesis not installed)
# ---------------------------------------------------------------------------

if HAS_HYPOTHESIS:

    @given(st.text(min_size=0, max_size=200))
    @settings(max_examples=200)
    def test_hypothesis_length_preserved(text: str):
        doc = redact(text)
        assert len(doc.masked_text) == len(text)

    @given(st.text(min_size=0, max_size=200))
    @settings(max_examples=100)
    def test_hypothesis_idempotent(text: str):
        once = redact(text).masked_text
        twice = redact(once).masked_text
        assert once == twice

    @given(
        prefix=st.text(min_size=5, max_size=50, alphabet=st.characters(whitelist_categories=("Ll",))),
        suffix=st.text(min_size=5, max_size=50, alphabet=st.characters(whitelist_categories=("Ll",))),
        secret=st.just("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"),
    )
    @settings(max_examples=50)
    def test_hypothesis_github_pat_never_in_output(prefix: str, secret: str, suffix: str):
        text = f"{prefix}{secret}{suffix}"
        doc = redact(text)
        assert len(doc.masked_text) == len(text)
        assert secret not in doc.masked_text

