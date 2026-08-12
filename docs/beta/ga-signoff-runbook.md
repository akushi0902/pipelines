# PipelineShield GA Sign-Off Runbook

**Version:** 1.0  
**Status:** Active  
**Applies to:** Private Beta 2026-12-01 to 2027-01-30  
**Owner:** Programme Owner (Head of Engineering)  

---

## 1. Purpose

This runbook defines the procedure for:
1. Evaluating the seven numeric GA gates against beta measurement data.
2. Recording a per-workspace sign-off.
3. Producing and sealing the immutable GA decision record.
4. Handling a missed gate: remediation, re-measurement, and re-evaluation.

GA proceeds **only** when all seven gates show `pass` in the same decision record.
No gate may be waived; a missed gate triggers this runbook's remediation path.

---

## 2. Evidence Sources Per Gate

| Gate | Evidence Source | Verification Command |
|------|----------------|----------------------|
| G1 — Workspace sign-off | `audit_event` rows with `action=beta_signoff_recorded` | `python -m pipelineshield.reporting.beta_metrics gates` |
| G2 — Accurate-and-actionable | Survey results CSV imported into platform fixture | `python -m pipelineshield.reporting.beta_metrics gates` |
| G3 — Distinct definitions | `analysis` JOIN `pipeline_definition` WHERE `is_sample=false` | `python -m pipelineshield.reporting.beta_metrics report` |
| G4 — Re-analysis rate | definitions with ≥2 analyses / total definitions | `python -m pipelineshield.reporting.beta_metrics report` |
| G5 — Median score delta | Per-definition (latest score − first score), median | `python -m pipelineshield.reporting.beta_metrics report` |
| G6 — Persona coverage | Distinct `actor_persona` in `audit_event` during beta window | `python -m pipelineshield.reporting.beta_metrics report` |
| G7 — Zero guardrails | Benchmark artefacts + authz denial audit count + purge breach count | `python -m pipelineshield.reporting.beta_metrics guardrails` |

---

## 3. Recording a Workspace Sign-Off

Sign-off records are written as **immutable** `audit_event` rows. The Python interface
is `record_signoff()` in `pipelineshield.reporting.beta_metrics`. No web or API
interface for sign-off exists; it must be called by a programme operator with
database access.

```python
from pipelineshield.reporting.beta_metrics import record_signoff, SignoffDecision

record_signoff(
    session=db_session,
    workspace_id=uuid.UUID("..."),
    owner_name="Jane Smith",
    decision=SignoffDecision.APPROVE,          # or APPROVE_WITH_CONDITIONS / REJECT
    conditions="Ensure sh-002 gate passes before GA",  # optional
    actor_id="operator@example.com",
)
```

The resulting `audit_event` row has:
- `action = "beta_signoff_recorded"`
- `resource_type = "workspace"`
- `resource_id = str(workspace_id)`
- `change_detail` = `{workspace_id, owner_name, decision, conditions, recorded_at}`

**Immutability:** The `audit_event` table has INSERT+SELECT privileges for the
application role but no UPDATE or DELETE. A recorded sign-off cannot be edited.
If a sign-off must be revised (e.g. conditions changed), a new row is appended with
`action = "beta_signoff_revised"` and the revision reason in `change_detail`.

---

## 4. Running the Gate Evaluation

```bash
# Full beta metrics report (JSON output)
python -m pipelineshield.reporting.beta_metrics report --output beta_metrics.json

# Gate evaluation only (exits non-zero if any gate fails)
python -m pipelineshield.reporting.beta_metrics gates --survey-results survey.json

# Guardrail evidence check
python -m pipelineshield.reporting.beta_metrics guardrails --evidence-dir /path/to/bundles
```

Output format (JSON):
```json
{
  "evaluated_at": "2027-01-30T12:00:00Z",
  "beta_window_start": "2026-12-01",
  "beta_window_end": "2027-01-30",
  "gates": [
    {
      "gate_id": "G1",
      "label": "Workspace sign-off",
      "threshold": "100%",
      "measured_value": "5/5 workspaces",
      "status": "pass"
    }
  ],
  "overall_status": "pass",
  "approvers": [],
  "decision": "pending"
}
```

---

## 5. Recording the GA Decision

When all seven gates show `pass`:

```python
from pipelineshield.reporting.beta_metrics import record_ga_decision

record_ga_decision(
    session=db_session,
    gate_results=evaluated_gates,   # list[GateResult] from evaluate_ga_gates()
    approver_ids=["alice@example.com", "bob@example.com"],
    actor_id="programme-owner@example.com",
)
```

This writes an `audit_event` row with:
- `action = "ga_decision_recorded"`
- `resource_type = "beta_programme"`
- `change_detail` = full gate evaluation summary, approvers, and decision

The record is append-only and retained for at least one year (Restricted retention
class).

---

## 6. Missed Gate: Remediation and Re-measurement

When any gate shows `fail` or `incomplete`:

### Step 1 — Triage (within 48 hours)

Convene the Engineering Lead, Programme Owner, and the relevant workspace owner.
Classify the root cause:
- **Data quality**: gate figure is wrong due to a measurement error → fix the query and
  re-run; no feature work required.
- **Product gap**: detection rate, persona coverage, or adoption below threshold due to
  a real gap → open a severity-1 work item.
- **Operational**: workspace sign-off missing or survey response too low due to
  participant dropout → extend the window per the procedure below.

### Step 2 — Remediation

| Gate | Typical remediation |
|------|---------------------|
| G1 (sign-off) | Contact workspace owner; if workspace has withdrawn, update the denominator per the workspace-withdrawal procedure |
| G2 (survey) | Re-survey respondents who did not yet complete; flag low-n personas |
| G3 (definitions) | Onboard additional pilot participants |
| G4 (re-analysis) | Review workflow: are users re-analysing after remediation? |
| G5 (score delta) | Check whether rules are scoring improvements; may indicate a rule regression |
| G6 (personas) | Recruit missing persona; one person per persona is sufficient |
| G7 (guardrails) | Any incident here is a P0; follow the security-incident runbook immediately |

### Step 3 — Window Extension

The beta window may be extended by a maximum of 30 days with explicit Programme Owner
sign-off recorded as an `audit_event` with `action = "beta_window_extended"`. Only
one extension is permitted. A second extension requires executive approval recorded as
a separate event.

### Step 4 — Re-measurement

After remediation, re-run the gate evaluation with the same command. The new
evaluation produces a new decision record (appended, not replacing the previous one).
All historical evaluations are retained for the audit trail.

---

## 7. Workspace Withdrawal Procedure

If a pilot workspace withdraws mid-beta:
1. Record the withdrawal as `audit_event` with `action = "beta_workspace_withdrawn"`.
2. Adjust the G1 denominator to exclude the withdrawn workspace **only if** fewer
   than 3 triage cycles have been completed for that workspace.
3. If 3 or more cycles have completed, the withdrawn workspace counts as unsigned-off
   and G1 fails unless the Programme Owner formally accepts the reduced cohort (also
   recorded as an audit event).
4. The remaining pilot workspaces must still satisfy all other gates independently.

---

## 8. Compliance Evidence Pack Index

The following artefacts are assembled into the SOC 2 compliance evidence pack
before the GA decision is sealed:

| Artefact | Location | Retention |
|----------|----------|-----------|
| Beta measurement plan | `docs/beta/beta-measurement-plan.md` | 1 year |
| GA sign-off runbook | `docs/beta/ga-signoff-runbook.md` | 1 year |
| Adjudication log (CSV + MD) | `docs/beta/adjudication-log.{csv,md}` | 1 year |
| Per-workspace sign-off records | `audit_event` rows `beta_signoff_recorded` | 1 year |
| Beta metrics report (final) | Generated JSON, stored in evidence bundle | 1 year |
| Survey results | Imported CSV, stored in evidence bundle | 1 year |
| Release-evidence bundles (all beta releases) | Produced by WO-048 pipeline stage | 1 year |
| GA decision record | `audit_event` row `ga_decision_recorded` | 1 year |
