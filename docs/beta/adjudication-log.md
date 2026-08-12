# PipelineShield Beta Adjudication Log

**Beta Window:** 2026-12-01 to 2027-01-30  
**Format:** One entry per finding class per triage cycle.  
**Machine-aggregatable version:** `adjudication-log.csv` (same directory).  

---

## Column Definitions

| Column | Description |
|--------|-------------|
| `triage_date` | ISO 8601 date of the triage session |
| `triage_cycle` | Integer cycle number (1–4) |
| `control_id` | Catalogue control identifier (e.g. `sh-001`) |
| `sample_analysis_ref` | Analysis UUID used as the reference instance |
| `expected_anchor_line` | Expected line from the ground-truth manifest |
| `anchoring_verdict` | `correct` / `off_by_N` / `unanchored` |
| `accuracy_verdict` | `true_positive` / `false_positive` / `not_assessable` |
| `adjudicator` | Name or email of the human reviewer |
| `notes` | Optional free-text clarification |

---

## Cycle 1 — 2026-12-12

*To be completed during Triage 1.*

| triage_date | triage_cycle | control_id | sample_analysis_ref | expected_anchor_line | anchoring_verdict | accuracy_verdict | adjudicator | notes |
|-------------|-------------|------------|---------------------|----------------------|-------------------|-----------------|-------------|-------|
| | | | | | | | | |

---

## Cycle 2 — 2026-12-26

*To be completed during Triage 2.*

| triage_date | triage_cycle | control_id | sample_analysis_ref | expected_anchor_line | anchoring_verdict | accuracy_verdict | adjudicator | notes |
|-------------|-------------|------------|---------------------|----------------------|-------------------|-----------------|-------------|-------|
| | | | | | | | | |

---

## Cycle 3 — 2027-01-09

*To be completed during Triage 3.*

| triage_date | triage_cycle | control_id | sample_analysis_ref | expected_anchor_line | anchoring_verdict | accuracy_verdict | adjudicator | notes |
|-------------|-------------|------------|---------------------|----------------------|-------------------|-----------------|-------------|-------|
| | | | | | | | | |

---

## Cycle 4 — 2027-01-23

*To be completed during Triage 4.*

| triage_date | triage_cycle | control_id | sample_analysis_ref | expected_anchor_line | anchoring_verdict | accuracy_verdict | adjudicator | notes |
|-------------|-------------|------------|---------------------|----------------------|-------------------|-----------------|-------------|-------|
| | | | | | | | | |

---

## Adjudication Rules (Summary)

- **true_positive**: Violation genuinely exists; anchor resolves within ±2 lines.
- **false_positive**: Violation does not exist or rule fired on a safe construct.
  All false positives must be escalated to the Engineering Lead and resolved before
  the GA decision is recorded.
- **not_assessable**: Scripted/dynamic construct; cannot be statically verified.
  These do not contribute to the accuracy rate numerator or denominator.
- **anchoring off_by_N**: Anchor resolves but is N lines from the expected line.
  off_by_1 and off_by_2 are acceptable (within tolerance). off_by_3+ requires
  investigation and must be documented in the notes column.
