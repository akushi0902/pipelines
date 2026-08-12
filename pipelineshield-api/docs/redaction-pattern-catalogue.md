# Redaction Pattern Catalogue

This document maps every pattern ID used by the PipelineShield secret redactor to its
human-readable description.  Pattern IDs appear inside masked tokens
(`[REDACTED:<pattern_id>]`) and in the `pattern_counts` field of a `RedactedDoc`.
They are safe to log, display in findings, or return in API responses.

> **Security invariant**: the `redaction_map` object (containing exact byte offsets of
> each secret span) is never serialised, logged, or passed outside the in-process request
> scope.  Only pattern IDs and counts are visible externally.

---

## Pattern IDs

### `github_pat`

**Description**: GitHub personal access token.

Matches classic tokens with the prefixes `ghp_`, `gho_`, `ghs_`, `ghu_`, and `ghr_`
(36 or more alphanumeric characters after the prefix), and fine-grained tokens with the
prefix `github_pat_` (22 or more alphanumeric/underscore characters after the prefix).

**Example shapes** (fake values):
- `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234`
- `github_pat_11AABBCCDDEE0000000000_xxxxxxxxxxxxxxxx`

---

### `gitlab_pat`

**Description**: GitLab personal access token.

Matches tokens with the prefix `glpat-` followed by 20 or more alphanumeric,
hyphen, or underscore characters.

**Example shapes** (fake values):
- `glpat-xYzAbCdEfGhIjKlMnOpQr`

---

### `aws_access_key_id`

**Description**: AWS access key ID.

Matches 20-character uppercase tokens beginning with `AKIA`, `ASIA`, `AROA`, `ANPA`,
`ANVA`, or `AIDA`, followed by exactly 16 uppercase alphanumeric characters.

**Example shapes** (fake values):
- `AKIAIOSFODNN7EXAMPLE`
- `ASIAIOSFODNN7EXAMPLE`

**Note**: The span is 20 characters, which is shorter than the full `[REDACTED:aws_access_key_id]`
token (27 characters).  The redactor falls back to a 20-character `X` run in this case
and records `aws_access_key_id` in the redaction map.

---

### `jwt`

**Description**: JSON Web Token (RFC 7519).

Matches three base64url-encoded segments separated by `.`, where the first segment
begins with `eyJ` (base64url encoding of `{"`).

**Example shape** (fake values):
- `eyJhbGci.eyJzdWIi.SflKxwRJ`

---

### `pem_block`

**Description**: PEM-encoded key or certificate block.

Matches the full block from `-----BEGIN <label>-----` through `-----END <label>-----`
including all intervening lines.  Newline positions are preserved inside the masked
output so downstream line and column offsets remain intact.

**Covered types**: RSA PRIVATE KEY, EC PRIVATE KEY, OPENSSH PRIVATE KEY, PRIVATE KEY,
CERTIFICATE, CERTIFICATE REQUEST, etc.

---

### `key_name_value`

**Description**: Secret assigned to a sensitive-named key.

Matches YAML `key: value` and shell `KEY=value` assignment shapes on a single line
where the key word contains any of: `secret`, `token`, `password`, `passwd`, `pwd`,
`credential`, or `key` (case-insensitive).  **Only the value span is masked**; the
key name itself is preserved so that finding reports can name the offending field
without leaking the credential.

**Coverage**: AWS secret access key, database passwords, API keys, bearer tokens,
and similar named secrets that lack a distinctive value-side prefix.

**Limitation**: Multi-line YAML block scalars and shell heredocs are not matched by
this pattern; they are covered by the PEM block pattern (if PEM-shaped) or the
`high_entropy` detector.

---

### `high_entropy`

**Description**: High-entropy unrecognised secret.

Detects candidate tokens of 32 or more printable non-whitespace characters drawn from
`[A-Za-z0-9+/=_-]` whose Shannon entropy exceeds **4.5 bits per character**.

**Rationale for threshold**: Hex-only strings (SHA pins, content digests) have a
theoretical maximum entropy of log₂(16) ≈ 4.0 bits/char and are therefore excluded.
Random base64 or alphanumeric secrets score ≥ 4.5 bits/char.

**Explicit exclusions** (not false-positives because entropy stays below threshold):
- SHA-256 hex digests (64 hex characters, ≈ 4.0 bits/char)
- Docker content digests (`sha256:<hex>`)
- Monotone repetition or dictionary words

This pattern runs **after** all explicit pattern passes to avoid double-masking
tokens already identified by a more specific rule.

---

## Length Preservation

Every masked token is byte-length identical to the original secret span:

| Span length ≥ token length | `[REDACTED:<pattern_id>]` padded with `X` to fill span |
| Span length < token length | `X` repeated to fill span (pattern_id recorded in map) |

Newlines inside multi-line spans (e.g. PEM blocks) are kept in place; only
non-newline characters are replaced.  This guarantees that **every downstream line
and column anchor** computed against the masked text remains valid.

---

## Registry Order

Patterns are applied in the following order.  When two patterns match the same
character span, the earlier-registered pattern wins.

| Order | Pattern ID            |
|-------|-----------------------|
| 1     | `github_pat`          |
| 2     | `gitlab_pat`          |
| 3     | `aws_access_key_id`   |
| 4     | `jwt`                 |
| 5     | `pem_block`           |
| 6     | `key_name_value`      |
| 7     | `high_entropy`        |
