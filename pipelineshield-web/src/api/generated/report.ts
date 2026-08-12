/**
 * GENERATED FILE — do not edit by hand.
 * Regenerate with: npm run generate:types
 * Source: pipelineshield-api OpenAPI schema (GET /api/v1/analyses/{id})
 *
 * Types mirror the FastAPI schemas in:
 *   pipelineshield-api/src/pipelineshield/api/v1/schemas/report.py
 */

export interface AnchorDetail {
  start_line: number;
  end_line: number | null;
  excerpt: string;
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingSource = 'deterministic' | 'ai';

export interface FindingSummary {
  finding_id: string;
  control_id: string;
  category: string;
  severity: FindingSeverity;
  title: string;
  anchor: AnchorDetail | null;
  source: FindingSource;
  requires_human_review: boolean;
}

export interface CategoryScoreItem {
  category: string;
  earned: number;
  possible: number;
  excluded_count: number;
}

export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface CoverageLimitationItem {
  kind: string;
  location: string;
  reason: string;
  affected_control_ids: string[];
}

export type HumanReviewReason = 'ai_advisory' | 'not_assessable';

export interface HumanReviewItem {
  finding_id: string | null;
  control_id: string;
  reason: HumanReviewReason;
}

export interface AnalysisReport {
  analysis_id: string;
  workspace_id: string;
  format: string;
  format_confidence: number;
  catalogue_version: number;
  total_score: number | null;
  letter_grade: string | null;
  unscorable_reason: string | null;
  category_scores: CategoryScoreItem[];
  severity_distribution: SeverityDistribution;
  findings: FindingSummary[];
  coverage_limitations: CoverageLimitationItem[];
  requires_human_review: HumanReviewItem[];
  advisory_disclaimer: string;
  created_at: string;
  /** Present when AI explanation pass degraded; deterministic score remains valid. */
  degraded_coverage_notice?: string | null;
}
