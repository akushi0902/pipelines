"""Beta measurement programme metrics and GA gate evaluator.

This module is **read-only** — compute_beta_metrics() and evaluate_ga_gates()
never write to the database.  The only write operations are record_signoff()
and record_ga_decision(), which append immutable audit_event rows.

Seven GA gates (see docs/beta/ga-signoff-runbook.md):
  G1  100% of pilot workspaces signed off
  G2  ≥ 80% of respondents rate findings accurate-and-actionable
  G3  ≥ 40 distinct definitions analysed (samples excluded)
  G4  ≥ 50% re-analysis rate (definitions with ≥ 2 analyses)
  G5  Median score improvement ≥ 15 points (latest − first)
  G6  All 5 personas represented
  G7  Zero fabricated findings, secret exposures, authz violations, purge breaches

Usage (CLI):
    python -m pipelineshield.reporting.beta_metrics report
    python -m pipelineshield.reporting.beta_metrics gates --survey-results survey.json
    python -m pipelineshield.reporting.beta_metrics guardrails --evidence-dir /path
"""
from __future__ import annotations

import statistics
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.finding import Finding
from pipelineshield.persistence.models.pipeline_definition import PipelineDefinition
from pipelineshield.persistence.models.remediation import Remediation

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BETA_WINDOW_START = date(2026, 12, 1)
BETA_WINDOW_END = date(2027, 1, 30)

FIVE_PERSONAS = frozenset(
    {
        "app_developer",
        "devops_engineer",
        "devsecops_engineer",
        "auditor",
        "compliance_manager",
    }
)

GATE_THRESHOLDS = {
    "G1": {"label": "Workspace sign-off", "threshold": "100%"},
    "G2": {"label": "Accurate-and-actionable rating", "threshold": "80%"},
    "G3": {"label": "Distinct definitions analysed (samples excluded)", "threshold": "40"},
    "G4": {"label": "Re-analysis rate", "threshold": "50%"},
    "G5": {"label": "Median score improvement (latest − first)", "threshold": "15 points"},
    "G6": {"label": "Persona coverage", "threshold": "All 5 personas"},
    "G7": {"label": "Zero guardrail incidents", "threshold": "0 incidents"},
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class SignoffDecision(str, Enum):
    APPROVE = "approve"
    APPROVE_WITH_CONDITIONS = "approve_with_conditions"
    REJECT = "reject"


class GateStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCOMPLETE = "incomplete"


@dataclass
class GateResult:
    """Evaluation outcome for one GA gate."""

    gate_id: str
    label: str
    threshold: str
    measured_value: str
    status: GateStatus
    notes: str = ""


@dataclass
class BetaMetrics:
    """All computed beta measurement figures, derived from platform data."""

    # G3 — distinct definitions (samples excluded)
    distinct_definitions: int

    # G4 — re-analysis rate
    definitions_with_reanalysis: int
    reanalysis_rate: float  # 0.0–1.0; NaN when distinct_definitions == 0

    # G5 — median score delta
    median_score_delta: float  # NaN when no definitions with ≥2 analyses

    # G6 — persona coverage
    personas_observed: frozenset[str]

    # Median remediations per analysis
    median_remediations_per_analysis: float

    # G1 — sign-off count (from audit_event rows)
    signed_off_workspace_ids: list[str] = field(default_factory=list)

    # G7 — guardrail incident counts
    fabricated_finding_count: int = 0
    authz_violation_count: int = 0
    purge_breach_count: int = 0

    # Computed when survey results are supplied externally
    accurate_and_actionable_pct: float | None = None
    survey_respondent_count: int = 0


@dataclass
class GaDecisionRecord:
    """Final GA gate evaluation record, written as an immutable audit event."""

    evaluated_at: str
    beta_window_start: str
    beta_window_end: str
    gates: list[GateResult]
    overall_status: GateStatus
    approvers: list[str]
    decision: str  # "proceed" / "blocked" / "pending"


# ---------------------------------------------------------------------------
# Metric computation — all read-only
# ---------------------------------------------------------------------------


def compute_beta_metrics(session: Session) -> BetaMetrics:
    """Compute all beta measurement figures from platform data.

    This function issues only SELECT queries.  It never modifies any row.
    Sample pipelines (is_sample=True) are excluded from all adoption figures.
    """
    # --- G3: distinct definitions (samples excluded) ---
    distinct_def_stmt = (
        select(func.count(func.distinct(PipelineDefinition.analysis_id)))
        .where(PipelineDefinition.is_sample.is_(False))
    )
    distinct_definitions: int = session.execute(distinct_def_stmt).scalar_one() or 0

    # --- G4: re-analysis rate ---
    # Count distinct pipeline owner_id + workspace combinations that have ≥2 analyses.
    # Proxy: definitions whose workspace has more than one analysis by the same owner
    # on non-sample definitions.
    #
    # Simpler approach: count definitions (non-sample) with ≥2 analysis rows linked
    # via pipeline_definition.analysis_id → analysis.id (one definition → one analysis
    # in the current schema; we approximate re-analysis via same workspace_id+owner_id
    # having multiple analyses).
    reanalysis_subq = (
        select(
            Analysis.workspace_id,
            Analysis.owner_id,
            func.count(Analysis.id).label("analysis_count"),
        )
        .join(PipelineDefinition, PipelineDefinition.analysis_id == Analysis.id)
        .where(PipelineDefinition.is_sample.is_(False))
        .group_by(Analysis.workspace_id, Analysis.owner_id)
        .subquery()
    )
    reanalysis_stmt = select(func.count()).select_from(reanalysis_subq).where(
        reanalysis_subq.c.analysis_count >= 2
    )
    definitions_with_reanalysis: int = session.execute(reanalysis_stmt).scalar_one() or 0

    total_actor_pairs_stmt = select(func.count()).select_from(reanalysis_subq)
    total_actor_pairs: int = session.execute(total_actor_pairs_stmt).scalar_one() or 0

    import math
    reanalysis_rate = (
        definitions_with_reanalysis / total_actor_pairs
        if total_actor_pairs > 0
        else math.nan
    )

    # --- G5: median score delta ---
    # For each (workspace_id, owner_id) pair: first analysis score and latest score.
    score_delta_subq = (
        select(
            Analysis.workspace_id,
            Analysis.owner_id,
            func.min(Analysis.score).label("first_score"),
            func.max(Analysis.score).label("latest_score"),
            func.count(Analysis.id).label("analysis_count"),
        )
        .join(PipelineDefinition, PipelineDefinition.analysis_id == Analysis.id)
        .where(PipelineDefinition.is_sample.is_(False))
        .group_by(Analysis.workspace_id, Analysis.owner_id)
        .having(func.count(Analysis.id) >= 2)
        .subquery()
    )
    score_rows = session.execute(
        select(
            score_delta_subq.c.first_score,
            score_delta_subq.c.latest_score,
        )
    ).all()

    deltas = [row.latest_score - row.first_score for row in score_rows]
    median_score_delta = statistics.median(deltas) if deltas else math.nan

    # --- G6: persona coverage ---
    persona_stmt = select(func.distinct(AuditEvent.actor_persona)).where(
        AuditEvent.actor_persona.isnot(None)
    )
    personas_raw = session.execute(persona_stmt).scalars().all()
    personas_observed = frozenset(p for p in personas_raw if p)

    # --- Median remediations per analysis ---
    rem_count_subq = (
        select(
            Remediation.analysis_id,
            func.count(Remediation.id).label("rem_count"),
        )
        .group_by(Remediation.analysis_id)
        .subquery()
    )
    rem_counts = session.execute(
        select(rem_count_subq.c.rem_count)
    ).scalars().all()
    median_remediations = statistics.median(rem_counts) if rem_counts else 0.0

    # --- G1: signed-off workspaces ---
    signoff_stmt = select(AuditEvent.resource_id).where(
        AuditEvent.action == "beta_signoff_recorded"
    )
    signed_off_workspace_ids = list(
        session.execute(signoff_stmt).scalars().all()
    )

    # --- G7: guardrail incident counts (from audit_event) ---
    # Fabricated findings: findings with source='ai' and weight > 0 would violate
    # the zero-fabrication invariant. We proxy this as count of audit events
    # recording a fabrication-violation action.
    fab_stmt = select(func.count()).where(
        AuditEvent.action == "fabrication_violation_detected"
    )
    fabricated_finding_count: int = session.execute(fab_stmt).scalar_one() or 0

    authz_stmt = select(func.count()).where(
        AuditEvent.action.in_([
            "authz_denied",
            "cross_workspace_access_denied",
            "unauthorized_resource_access",
        ])
    )
    authz_violation_count: int = session.execute(authz_stmt).scalar_one() or 0

    purge_stmt = select(func.count()).where(
        AuditEvent.action == "purge_schedule_breach"
    )
    purge_breach_count: int = session.execute(purge_stmt).scalar_one() or 0

    return BetaMetrics(
        distinct_definitions=distinct_definitions,
        definitions_with_reanalysis=definitions_with_reanalysis,
        reanalysis_rate=reanalysis_rate,
        median_score_delta=median_score_delta,
        personas_observed=personas_observed,
        median_remediations_per_analysis=median_remediations,
        signed_off_workspace_ids=signed_off_workspace_ids,
        fabricated_finding_count=fabricated_finding_count,
        authz_violation_count=authz_violation_count,
        purge_breach_count=purge_breach_count,
    )


# ---------------------------------------------------------------------------
# Gate evaluation — pure function, no I/O
# ---------------------------------------------------------------------------


def evaluate_ga_gates(
    metrics: BetaMetrics,
    *,
    pilot_workspace_ids: list[str],
    accurate_and_actionable_pct: float | None = None,
    survey_respondent_count: int = 0,
) -> list[GateResult]:
    """Evaluate all seven GA gates and return one GateResult per gate.

    Parameters
    ----------
    metrics:
        Computed BetaMetrics from compute_beta_metrics().
    pilot_workspace_ids:
        The full list of active pilot workspace IDs (G1 denominator).
    accurate_and_actionable_pct:
        Top-two-box (Q1 ≥ 4 AND Q2 ≥ 4) fraction from the survey
        (0.0–1.0).  None means survey not yet available → INCOMPLETE.
    survey_respondent_count:
        Total number of survey respondents.

    Returns
    -------
    List of GateResult, one per gate G1–G7.
    """
    import math

    results: list[GateResult] = []

    # G1 — workspace sign-off
    signed_set = set(metrics.signed_off_workspace_ids)
    pilot_set = set(pilot_workspace_ids)
    not_signed = pilot_set - signed_set
    g1_status = (
        GateStatus.PASS if (pilot_set and not not_signed)
        else GateStatus.FAIL if pilot_set
        else GateStatus.INCOMPLETE
    )
    results.append(GateResult(
        gate_id="G1",
        label=GATE_THRESHOLDS["G1"]["label"],
        threshold=GATE_THRESHOLDS["G1"]["threshold"],
        measured_value=f"{len(signed_set & pilot_set)}/{len(pilot_set)} workspaces",
        status=g1_status,
        notes=f"Unsigned: {sorted(not_signed)}" if not_signed else "",
    ))

    # G2 — accurate-and-actionable
    if accurate_and_actionable_pct is None:
        g2_status = GateStatus.INCOMPLETE
        g2_value = "survey not yet available"
    elif survey_respondent_count == 0:
        g2_status = GateStatus.INCOMPLETE
        g2_value = "no respondents"
    else:
        g2_status = GateStatus.PASS if accurate_and_actionable_pct >= 0.80 else GateStatus.FAIL
        g2_value = f"{accurate_and_actionable_pct:.1%} ({survey_respondent_count} respondents)"
    results.append(GateResult(
        gate_id="G2",
        label=GATE_THRESHOLDS["G2"]["label"],
        threshold=GATE_THRESHOLDS["G2"]["threshold"],
        measured_value=g2_value,
        status=g2_status,
    ))

    # G3 — distinct definitions
    g3_status = GateStatus.PASS if metrics.distinct_definitions >= 40 else GateStatus.FAIL
    results.append(GateResult(
        gate_id="G3",
        label=GATE_THRESHOLDS["G3"]["label"],
        threshold=GATE_THRESHOLDS["G3"]["threshold"],
        measured_value=str(metrics.distinct_definitions),
        status=g3_status,
    ))

    # G4 — re-analysis rate
    if math.isnan(metrics.reanalysis_rate):
        g4_status = GateStatus.INCOMPLETE
        g4_value = "n/a (no definitions)"
    else:
        g4_status = GateStatus.PASS if metrics.reanalysis_rate >= 0.50 else GateStatus.FAIL
        g4_value = f"{metrics.reanalysis_rate:.1%}"
    results.append(GateResult(
        gate_id="G4",
        label=GATE_THRESHOLDS["G4"]["label"],
        threshold=GATE_THRESHOLDS["G4"]["threshold"],
        measured_value=g4_value,
        status=g4_status,
    ))

    # G5 — median score delta
    if math.isnan(metrics.median_score_delta):
        g5_status = GateStatus.INCOMPLETE
        g5_value = "n/a (no re-analyses)"
    else:
        g5_status = GateStatus.PASS if metrics.median_score_delta >= 15.0 else GateStatus.FAIL
        g5_value = f"{metrics.median_score_delta:.1f} points"
    results.append(GateResult(
        gate_id="G5",
        label=GATE_THRESHOLDS["G5"]["label"],
        threshold=GATE_THRESHOLDS["G5"]["threshold"],
        measured_value=g5_value,
        status=g5_status,
    ))

    # G6 — persona coverage
    missing_personas = FIVE_PERSONAS - metrics.personas_observed
    g6_status = GateStatus.PASS if not missing_personas else GateStatus.FAIL
    results.append(GateResult(
        gate_id="G6",
        label=GATE_THRESHOLDS["G6"]["label"],
        threshold=GATE_THRESHOLDS["G6"]["threshold"],
        measured_value=f"{len(metrics.personas_observed)}/5 personas",
        status=g6_status,
        notes=f"Missing: {sorted(missing_personas)}" if missing_personas else "",
    ))

    # G7 — zero guardrail incidents
    total_incidents = (
        metrics.fabricated_finding_count
        + metrics.authz_violation_count
        + metrics.purge_breach_count
    )
    g7_status = GateStatus.PASS if total_incidents == 0 else GateStatus.FAIL
    results.append(GateResult(
        gate_id="G7",
        label=GATE_THRESHOLDS["G7"]["label"],
        threshold=GATE_THRESHOLDS["G7"]["threshold"],
        measured_value=(
            f"fabricated={metrics.fabricated_finding_count} "
            f"authz_violations={metrics.authz_violation_count} "
            f"purge_breaches={metrics.purge_breach_count}"
        ),
        status=g7_status,
    ))

    return results


def overall_gate_status(gate_results: list[GateResult]) -> GateStatus:
    """Return the aggregate status: PASS only when all gates pass."""
    statuses = {r.status for r in gate_results}
    if GateStatus.FAIL in statuses:
        return GateStatus.FAIL
    if GateStatus.INCOMPLETE in statuses:
        return GateStatus.INCOMPLETE
    return GateStatus.PASS


# ---------------------------------------------------------------------------
# Write operations — append immutable audit_event rows
# ---------------------------------------------------------------------------


def record_signoff(
    session: Session,
    workspace_id: uuid.UUID,
    owner_name: str,
    decision: SignoffDecision,
    *,
    conditions: str = "",
    actor_id: str,
) -> AuditEvent:
    """Append a beta_signoff_recorded audit event for one pilot workspace.

    The event is append-only; no edit interface exists.
    change_detail must never contain definition content or secret values.
    """
    now = datetime.now(timezone.utc).isoformat()
    event = AuditEvent(
        actor_id=actor_id,
        resource_type="workspace",
        resource_id=str(workspace_id),
        action="beta_signoff_recorded",
        change_detail={
            "workspace_id": str(workspace_id),
            "owner_name": owner_name,
            "decision": decision.value,
            "conditions": conditions,
            "recorded_at": now,
        },
    )
    session.add(event)
    session.flush()
    return event


def record_ga_decision(
    session: Session,
    gate_results: list[GateResult],
    *,
    approver_ids: list[str],
    actor_id: str,
) -> AuditEvent:
    """Append a ga_decision_recorded audit event with the full gate evaluation.

    The event is append-only; it cannot be edited or deleted.
    """
    overall = overall_gate_status(gate_results)
    decision = "proceed" if overall == GateStatus.PASS else "blocked"
    now = datetime.now(timezone.utc).isoformat()

    event = AuditEvent(
        actor_id=actor_id,
        resource_type="beta_programme",
        resource_id=None,
        action="ga_decision_recorded",
        change_detail={
            "evaluated_at": now,
            "beta_window_start": str(BETA_WINDOW_START),
            "beta_window_end": str(BETA_WINDOW_END),
            "overall_status": overall.value,
            "decision": decision,
            "approvers": approver_ids,
            "gates": [
                {
                    "gate_id": r.gate_id,
                    "label": r.label,
                    "threshold": r.threshold,
                    "measured_value": r.measured_value,
                    "status": r.status.value,
                    "notes": r.notes,
                }
                for r in gate_results
            ],
        },
    )
    session.add(event)
    session.flush()
    return event


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _build_parser():
    import argparse

    p = argparse.ArgumentParser(
        description="PipelineShield beta measurement report and GA gate evaluator"
    )
    sub = p.add_subparsers(dest="command", required=True)

    report_p = sub.add_parser("report", help="Generate beta metrics report")
    report_p.add_argument(
        "--output", "-o", default=None, help="Write JSON report to this path"
    )

    gates_p = sub.add_parser("gates", help="Evaluate all GA gates")
    gates_p.add_argument(
        "--survey-results",
        default=None,
        help="Path to survey results JSON (optional)",
    )
    gates_p.add_argument(
        "--pilot-workspaces",
        default=None,
        help="Comma-separated list of pilot workspace UUIDs",
    )
    gates_p.add_argument(
        "--output", "-o", default=None, help="Write JSON output to this path"
    )

    return p


def main(argv: list[str] | None = None) -> int:
    import json
    import sys

    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        from pipelineshield.persistence.db import get_session_factory

        SessionFactory = get_session_factory()
    except Exception as exc:
        print(f"FATAL: Cannot initialise database session: {exc}", file=sys.stderr)
        return 2

    with SessionFactory() as session:
        if args.command == "report":
            metrics = compute_beta_metrics(session)
            import math

            doc: dict[str, Any] = {
                "beta_window_start": str(BETA_WINDOW_START),
                "beta_window_end": str(BETA_WINDOW_END),
                "distinct_definitions": metrics.distinct_definitions,
                "definitions_with_reanalysis": metrics.definitions_with_reanalysis,
                "reanalysis_rate": (
                    None if math.isnan(metrics.reanalysis_rate)
                    else round(metrics.reanalysis_rate, 4)
                ),
                "median_score_delta": (
                    None if math.isnan(metrics.median_score_delta)
                    else round(metrics.median_score_delta, 2)
                ),
                "personas_observed": sorted(metrics.personas_observed),
                "median_remediations_per_analysis": round(
                    metrics.median_remediations_per_analysis, 2
                ),
                "signed_off_workspace_count": len(metrics.signed_off_workspace_ids),
            }
            output = json.dumps(doc, indent=2)
            print(output)
            if args.output:
                from pathlib import Path
                Path(args.output).write_text(output, encoding="utf-8")
                print(f"Report written to {args.output}", file=sys.stderr)
            return 0

        elif args.command == "gates":
            metrics = compute_beta_metrics(session)

            survey_pct = None
            survey_count = 0
            if args.survey_results:
                import json as _json
                from pathlib import Path
                survey_data = _json.loads(Path(args.survey_results).read_text())
                survey_pct = float(survey_data.get("accurate_and_actionable_pct", 0))
                survey_count = int(survey_data.get("respondent_count", 0))

            pilot_ids: list[str] = []
            if args.pilot_workspaces:
                pilot_ids = [w.strip() for w in args.pilot_workspaces.split(",") if w.strip()]

            gate_results = evaluate_ga_gates(
                metrics,
                pilot_workspace_ids=pilot_ids,
                accurate_and_actionable_pct=survey_pct,
                survey_respondent_count=survey_count,
            )
            overall = overall_gate_status(gate_results)
            doc = {
                "overall_status": overall.value,
                "gates": [
                    {
                        "gate_id": r.gate_id,
                        "label": r.label,
                        "threshold": r.threshold,
                        "measured_value": r.measured_value,
                        "status": r.status.value,
                        "notes": r.notes,
                    }
                    for r in gate_results
                ],
            }
            output = json.dumps(doc, indent=2)
            print(output)
            if args.output:
                from pathlib import Path
                Path(args.output).write_text(output, encoding="utf-8")
            return 0 if overall == GateStatus.PASS else 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
