# PipelineShield Private Beta Measurement Plan

**Version:** 1.0  
**Status:** Active  
**Beta Window:** 2026-12-01 to 2027-01-30  
**Review Cadence:** Fortnightly (every two weeks)  
**Programme Owner:** Head of Engineering  

---

## 1. Programme Overview

The PipelineShield private beta runs in a closed cohort of pilot workspaces from
2026-12-01 through 2027-01-30 (nine weeks). The goal is to validate accuracy,
actionability, and adoption figures against seven numeric GA gates before general
availability is declared.

GA proceeds **only** when all seven gates pass on the same measurement date. A
missed gate triggers the documented remediation-and-recheck path; no gate may be
waived by exception.

---

## 2. Participant Roles

| Role | Responsibility |
|------|---------------|
| Programme Owner | Final GA sign-off authority; escalation point for blocked gates |
| Workspace Owner | Per-workspace sign-off record; submits end-of-beta survey |
| Security Champion | Represents devsecops_engineer persona; leads finding triage |
| DevOps Lead | Represents devops_engineer persona |
| App Developer Rep | Represents app_developer persona |
| Auditor Rep | Represents auditor persona |
| Compliance Officer | Represents compliance_manager persona |
| Engineering Lead | Accuracy triage; owns adjudication log |

All five personas (`app_developer`, `devops_engineer`, `devsecops_engineer`,
`auditor`, `compliance_manager`) must be represented in the pilot cohort.

---

## 3. Fortnightly Triage Cadence

| Session | Date | Focus |
|---------|------|-------|
| Triage 1 | 2026-12-12 | Baseline accuracy assessment; adjudication log seeded |
| Triage 2 | 2026-12-26 | Mid-beta accuracy delta; survey instrument dry-run |
| Triage 3 | 2027-01-09 | Adoption rate check; re-analysis rate calculation |
| Triage 4 | 2027-01-23 | Final gate evaluation; GA decision record drafted |
| Close-out | 2027-01-30 | Sign-off record submission; evidence pack sealed |

Each triage session produces:
- An updated adjudication log entry per finding class reviewed.
- A generated beta metrics report exported from the platform (aggregates only, no
  definition content).
- Action items assigned to named owners with a resolution date.

---

## 4. Adjudication Log Format

The adjudication log is maintained at `docs/beta/adjudication-log.md` (human-readable
summary) and `docs/beta/adjudication-log.csv` (machine-aggregatable). One row per
finding class per triage cycle.

### Required columns (CSV)

| Column | Description |
|--------|-------------|
| `triage_date` | ISO 8601 date (YYYY-MM-DD) |
| `control_id` | Catalogue control identifier (e.g. `sh-001`) |
| `sample_analysis_ref` | Analysis UUID used as the reference instance |
| `expected_anchor_line` | Expected line number from ground-truth manifest |
| `anchoring_verdict` | `correct` / `off_by_N` / `unanchored` |
| `accuracy_verdict` | `true_positive` / `false_positive` / `not_assessable` |
| `adjudicator` | Name or email of the human reviewer |
| `triage_cycle` | Integer triage cycle number (1–4) |
| `notes` | Free-text clarification (optional) |

### Adjudication rules

- A finding is a **true positive** when the control violation genuinely exists in the
  pipeline and the anchor resolves to the correct or near-correct (±2 lines) location.
- A finding is a **false positive** when the violation does not exist or the rule
  fired on a safe construct. All false positives are escalated to Engineering Lead.
- **not_assessable** is recorded when the construct is scripted/dynamic and cannot be
  statically verified.
- A false positive rate > 0 unblocks the fabrication gate and **must** be resolved
  before the GA decision is recorded.

---

## 5. End-of-Beta Survey Instrument

The survey is administered per-persona in the final week of the beta window
(2027-01-23 to 2027-01-30). All questions use a five-point Likert scale
(1 = Strongly Disagree … 5 = Strongly Agree).

### Question set (all personas)

| # | Question |
|---|----------|
| Q1 | The security findings I reviewed were accurate. |
| Q2 | The recommended remediations were actionable within my team's workflow. |
| Q3 | The findings clearly explained *why* each issue matters. |
| Q4 | I would re-analyse the same pipeline after applying remediations. |
| Q5 | I would recommend PipelineShield to a colleague in a similar role. |

### Persona-specific additional questions

**app_developer / devops_engineer:**  
Q6. The score and grade helped me prioritise which issues to fix first.

**devsecops_engineer / auditor:**  
Q6. The control coverage report gave me an honest picture of what could not be assessed.  
Q7. I trust the deterministic findings as input to a compliance audit.

**compliance_manager:**  
Q6. The posture dashboard gave me sufficient evidence to track progress across workspaces.  
Q7. The data retention and purge receipts satisfy our compliance obligations.

### Accurate-and-actionable threshold

A respondent is counted as **accurate-and-actionable** when they rate **both** Q1 ≥ 4
and Q2 ≥ 4 (top-two-box: Agree or Strongly Agree). The GA gate requires ≥ 80% of all
respondents meeting this threshold. Personas with fewer than 3 respondents are flagged
as **low-n** and reported separately; they still count toward the overall percentage
but the low-n flag is noted in the decision record.

---

## 6. Seven Numeric GA Gates

| # | Gate | Threshold | Evidence Source |
|---|------|-----------|-----------------|
| G1 | Pilot workspace sign-off | 100% of active pilot workspaces | `audit_event` with `action=beta_signoff_recorded` |
| G2 | Accurate-and-actionable rating | ≥ 80% of respondents | Survey results (top-two-box Q1+Q2 ≥ 4) |
| G3 | Distinct definitions analysed | ≥ 40 (samples excluded) | `pipeline_definition.is_sample = false` |
| G4 | Re-analysis rate | ≥ 50% of definitions with ≥ 2 analyses | `analysis` count per `pipeline_definition` |
| G5 | Median score improvement | ≥ 15 points (latest − first) | Per-definition score delta, median |
| G6 | Persona coverage | All 5 personas represented | Distinct `actor_persona` in audit events |
| G7 | Guardrail zero-incident | Zero fabricated findings, zero secret exposure, zero authz violations, zero purge breaches | Benchmark artefacts + audit trail |

---

## 7. Non-production Environment Guard

The beta reporting command may only run against the production trust boundary. A
configuration validator in `pipelineshield-api` refuses to boot or run the report when
the environment profile is `dev` or `staging` and a real-data flag or production DSN
is configured. This ensures beta figures are never accidentally computed against
synthetic or staging data and reported as real.

---

## 8. Reporting Principles

- All figures are generated inside the platform trust boundary from aggregates only.
- No definition content, secret values, or workspace-identifiable data leaves the
  platform in any report.
- The gate evaluation command is read-only; it cannot modify any platform record.
- The GA decision and sign-off records are written as append-only `audit_event` rows
  and are retained for at least one year.
