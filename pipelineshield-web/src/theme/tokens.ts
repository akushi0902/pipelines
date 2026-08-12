/**
 * Semantic design-token helpers for severity levels and score grades.
 *
 * All colour tokens live in src/styles/tokens.css as CSS custom properties
 * (verified for WCAG 2.2 AA in both light and dark themes).  This module
 * provides typed TypeScript helpers so components never hard-code token names.
 *
 * Severity is always conveyed by text label AND shape, not colour alone.
 */

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Human-readable label for each severity level. */
export const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Informational',
};

/** Tailwind text-colour class for each severity (supplementary to shape). */
export const SEVERITY_COLOR_CLASSES: Record<SeverityLevel, string> = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  info: 'text-sev-info',
};

/** Tailwind background surface class for severity badges. */
export const SEVERITY_BG_CLASSES: Record<SeverityLevel, string> = {
  critical: 'bg-error-surface',
  high: 'bg-warning-surface',
  medium: 'bg-warning-surface',
  low: 'bg-success-surface',
  info: 'bg-info-surface',
};

/**
 * Assessed-coverage grade language.
 * BR-02: grade language must describe assessed-control coverage only;
 * no string may assert the pipeline is secure, compliant, or certified.
 */
export const GRADE_DESCRIPTORS: Record<string, string> = {
  A: 'strong coverage of assessed controls',
  B: 'good coverage of assessed controls',
  C: 'moderate coverage of assessed controls',
  D: 'limited coverage of assessed controls',
  F: 'minimal coverage of assessed controls',
};

/**
 * Returns the full assessed-coverage grade label.
 * Example: gradeLabel('A') → 'Grade A — strong coverage of assessed controls'
 */
export function gradeLabel(grade: string): string {
  const descriptor = GRADE_DESCRIPTORS[grade] ?? 'coverage of assessed controls';
  return `Grade ${grade} — ${descriptor}`;
}

/**
 * Returns the Tailwind text-colour class for a letter grade.
 * Grades are: A (success), B (success), C (warning), D (warning), F (error).
 */
export function gradeColorClass(grade: string): string {
  if (grade === 'A' || grade === 'B') return 'text-success';
  if (grade === 'C' || grade === 'D') return 'text-warning';
  return 'text-error';
}

/** Normalise API severity strings to the typed SeverityLevel union. */
export function normaliseSeverity(raw: string): SeverityLevel {
  if (raw === 'critical') return 'critical';
  if (raw === 'high') return 'high';
  if (raw === 'medium') return 'medium';
  if (raw === 'low') return 'low';
  return 'info';
}
