/**
 * TypeScript types derived from the PipelineShield API OpenAPI schema.
 * All types use `unknown` for untrusted fields that must be narrowed explicitly.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ChangeTarget = 'category' | 'control';

export interface GradeBandOut {
  grade: string;
  min_score: number;
  max_score: number;
}

export interface ControlOut {
  id: string;
  category_id: string;
  severity: Severity;
  enabled: boolean;
  reference_tools: string[];
}

export interface CategoryOut {
  id: string;
  name: string;
  weight: number;
  enabled: boolean;
}

export interface CatalogueGetResponse {
  version: number;
  status: string;
  created_at: string;
  created_by: string;
  grade_bands: GradeBandOut[];
  categories: CategoryOut[];
  controls: ControlOut[];
}

export interface ChangeFields {
  weight?: number;
  enabled?: boolean;
  severity?: Severity;
  reference_tools?: string[];
}

export interface ChangeOp {
  target: ChangeTarget;
  id: string;
  fields: ChangeFields;
}

export interface CataloguePatchRequest {
  base_version: number;
  rationale: string;
  changes: ChangeOp[];
}

export interface DiffEntry {
  path: string;
  old_value: unknown;
  new_value: unknown;
}

export interface CataloguePatchResponse {
  version: number;
  created_at: string;
  created_by: string;
  diff: DiffEntry[];
  snapshot: CatalogueGetResponse;
}

export interface FieldError {
  field: string;
  message: string;
}

export interface ApiErrorBody {
  type: string;
  title: string;
  status: number;
  detail: string;
  errors: FieldError[];
}

export interface AuditEventItem {
  id: string;
  occurred_at: string;
  actor_id: string;
  actor_reference: string | null;
  actor_persona: string | null;
  workspace_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  change_detail: Record<string, unknown>;
  correlation_id: string | null;
}

export interface AuditEventsResponse {
  items: AuditEventItem[];
  next_cursor: string | null;
  total_returned: number;
}

// ---------------------------------------------------------------------------
// Admin / Role Binding types
// ---------------------------------------------------------------------------

export type Persona =
  | 'app_developer'
  | 'devops_engineer'
  | 'devsecops_engineer'
  | 'appsec_lead'
  | 'engineering_manager';

export const VALID_PERSONAS: Persona[] = [
  'app_developer',
  'devops_engineer',
  'devsecops_engineer',
  'appsec_lead',
  'engineering_manager',
];

export interface RoleBindingItem {
  id: string;
  app_user_id: string;
  masked_email: string;
  display_name: string;
  persona: Persona;
  granted_by_id: string | null;
  granted_at: string;
  revoked_at: string | null;
}

export interface RoleBindingListResponse {
  items: RoleBindingItem[];
  total: number;
}

export interface GrantBindingRequest {
  user_id: string;
  persona: Persona;
}

export interface GrantBindingResponse extends RoleBindingItem {}

export interface ChangeBindingRequest {
  persona: Persona;
}

export interface GroupPersonaMappingItem {
  id: string;
  idp_group: string;
  workspace_id: string;
  persona: Persona;
  precedence: number;
  created_at: string;
}

export interface GroupPersonaMappingListResponse {
  items: GroupPersonaMappingItem[];
  total: number;
}
