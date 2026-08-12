# Forge Implementation Log

| Field | Value |
|-------|-------|
| Project | 6172f887-3aab-4aac-93a9-955463ad895e |
| Branch | forge/pipeline-shield-ai-ci-cd-secur-d374f19a-run5-51wo |
| Started | 2026-08-11T11:57:55Z |

---

## WO-001: User Story: WO-001 - Baseline PostgreSQL schema and least-privilege migrations
- **Status:** completed
- **Commit:** `a8b9bae`
- **Files:** 7 (+68/-30)
- **Duration:** 825ss
- **Approach:** The greenfield pipelineshield-api scaffold was already present with all twelve SQLAlchemy 2.0 models, the Alembic baseline migration, repository interfaces/implementations, KeyProvider envelope encryption, integration tests, and seed fixture. The implementation required fixing three SQLAlchemy 2.0 compatibility issues that would have caused test failures: (1) removed the deprecated autocommit=False parameter from sessionmaker in db.py, (2) fixed alembic/env.py to honour a URL already set programmatically (e.g. by the integration test fixture) rather than always overwriting it with DATABASE_URL from the OS environment, and (3) updated the unit test session fixture to use SQLAlchemy 2.0 style with StaticPool and Session(engine) rollback isolation instead of the connection-level bind pattern. Also cleaned up unused imports in audit_event.py.

## WO-009: User Story: WO-009 - Versioned Immutable Control Catalogue Schema and Seed
- **Status:** completed
- **Commit:** `3a65bca`
- **Files:** 20 (+1816/-58)
- **Duration:** 1199ss
- **Approach:** Implemented the versioned immutable control catalogue as an append-only SQLAlchemy 2.0 model with a dialect-aware DialectJSON type (JSONB on PostgreSQL, JSON on SQLite). Added a forward-only Alembic 0002 migration using batch_alter_table for cross-dialect compatibility that renames the scaffold columns (version_number→version, description→change_notes, controls→snapshot) and adds status, grade_bands, created_by (FK app_user), and content_checksum. Defined full Pydantic v2 CatalogueSnapshot schemas with model_validators for weight totals, unique IDs, severity enum, and grade band coverage 0-100. Implemented CatalogueRepository (abstract + SQLAlchemy) with get_active, get_by_version, list_versions, and create_version (INSERT-only, raises CatalogueVersionConflictError on duplicate). Added an idempotent seed routine that validates the committed catalogue_v1.json fixture before inserting.

## WO-030: User Story: WO-030 - Enterprise DevSecOps posture dashboard with pre-aggregated queries
- **Status:** completed
- **Commit:** `590a04a`
- **Files:** 17 (+495/-1)
- **Duration:** 381ss
- **Approach:** N/A

## WO-002: User Story: WO-002 - Length-preserving secret redactor at ingestion boundary
- **Status:** completed
- **Commit:** `b75e5b7`
- **Files:** 5 (+0/-0)
- **Duration:** 1024ss
- **Approach:** Implemented a pure, framework-free analysis module with an ordered immutable pattern registry (6 explicit RedactionPattern entries + Shannon-entropy detector) and a single-pass non-overlapping masking algorithm. The redactor collects all regex spans plus high-entropy candidates, resolves overlaps by (start, registry_index) order, and applies a newline-preserving length-exact mask (_make_mask). RedactedDoc is a frozen Pydantic model with redaction_map excluded from serialisation (Field(exclude=True)). A ThreadPoolExecutor timeout guard prevents catastrophic-backtracking DoS. Structured logging emits per-pattern counts only.

## WO-010: User Story: WO-010 - Catalogue Read and Version-Creating PATCH Endpoints
- **Status:** completed
- **Commit:** `08a6a75`
- **Files:** 15 (+1370/-5)
- **Duration:** 571ss
- **Approach:** Created the full catalogue API stack: Pydantic v2 schemas with strict extra='forbid' on ChangeFields, a deny-by-default AuthzGuard with PERSONA_CAPABILITIES map, a CatalogueService that applies change ops in-memory then revalidates through CatalogueSnapshot, and a thin FastAPI router. All three writes (new version INSERT, predecessor status UPDATE via new mark_superseded method, audit event INSERT) flush inside the caller's transaction so a rollback cleans them all up. Rationale text is redacted via the WO-002 redactor before being stored in change_detail. Tests use FastAPI TestClient with dep overrides for session and actor.

## WO-036: User Story: WO-036 - OIDC PKCE login with server-side Redis session lifecycle
- **Status:** completed
- **Commit:** `bc377a5`
- **Files:** 15 (+0/-0)
- **Duration:** 980ss
- **Approach:** Implemented the full backend OIDC PKCE authentication stack. AuthConfig uses pydantic-settings and fails closed if any required secret (oidc_issuer, oidc_client_id, oidc_client_secret, oidc_redirect_uri, redis_url) is absent. RedisSessionStore stores opaque session IDs as Redis hashes with sliding EXPIRE on every read and application-code absolute-lifetime enforcement. RedisLoginStateStore keeps OIDC state params (nonce, code_challenge) for 5 minutes with atomic single-use pop (replay protection). AuthModule orchestrates begin_login (state/nonce generation, PKCE challenge validation, IdP URL build), complete_callback (state pop, S256 server-side PKCE verification, code exchange via httpx, id_token verification via PyJWT+JWKS, JIT app_user upsert, role_binding resolution, session creation, audit events), resolve_session (sliding TTL refresh), and terminate_session. The thin AuthRouter delegates everything to AuthModule, sets httpOnly/Secure/SameSite=Lax cookies, and maps errors to RFC 7807 structured bodies. Migration 0004 adds idp_subject (unique) and last_login_at to app_user with an explicit comment forbidding password columns.

## WO-038: User Story: WO-038 - Append-only audit event store with completeness enforcement
- **Status:** completed
- **Commit:** `9cd6497`
- **Files:** 15 (+1599/-20)
- **Duration:** 622ss
- **Approach:** Implemented structural audit immutability and completeness enforcement. Migration 0005 adds actor_user_id, actor_reference, workspace_id, source_ip_masked, user_agent_hash columns to audit_event, installs BEFORE UPDATE OR DELETE triggers (PostgreSQL PL/pgSQL RAISE EXCEPTION + SQLite RAISE(ABORT)) as defence against grant drift, adds query indexes, and adds a partial index on pipeline_definition for the purge worker. ContentGuard runs in reject mode — scans change_detail for secret patterns (GitHub PAT, AWS key, JWT, PEM, key=value, high-entropy) and raises AuditContentViolation with field path but never the value; oversized payloads are truncated with _truncated marker. AuditWriter is the single write path that runs the content guard and appends through AuditRepository. AuditRepository gained cursor-paginated list_scoped with workspace scoping and full filter support. AuditRouter exposes GET /api/v1/audit-events guarded by audit:read (devsecops_engineer, appsec_lead); no mutating endpoints exist, verified by OpenAPI spec test. Tests cover all patterns, nested scanning, entropy detection, truncation, immutability triggers, single-writer static analysis, repository surface, router authorization, and completeness registry.

## WO-045: User Story: WO-045 - Build Seeded Benchmark Corpus With Ground-Truth Manifest
- **Status:** completed
- **Commit:** `85c649e`
- **Files:** 16 (+0/-0)
- **Duration:** 766ss
- **Approach:** N/A

## WO-003: User Story: WO-003 - Synchronous analysis ingestion endpoint with bounded payloads
- **Status:** completed
- **Commit:** `0b7ab1e`
- **Files:** 1 (+0/-0)
- **Duration:** 685ss
- **Approach:** N/A

## WO-011: User Story: WO-011 - Immutable Audit Trail Writer and Query Endpoint
- **Status:** completed
- **Commit:** `5b78151`
- **Files:** 8 (+983/-5)
- **Duration:** 816ss
- **Approach:** N/A

## WO-013: User Story: WO-013 - Pin Analyses to Catalogue Version for Reproducible Scoring
- **Status:** completed
- **Commit:** `888c2a1`
- **Files:** 8 (+0/-0)
- **Duration:** 819ss
- **Approach:** Implemented reproducible catalogue-pinned scoring via a pure ScoringEngine service injected with an immutable CatalogueSnapshot frozen at request start. Migration 0007 adds a composite index on (catalogue_version_id, created_at DESC). The ScoringEngine uses stable sorted iteration (sorted by category.id, control.id) to guarantee determinism; zero-denominator (all categories fully-NA) returns an unscorable result with no ZeroDivisionError. AnalysisOrchestrator resolves the active catalogue snapshot exactly once, passes catalogue_version_id to _persist, and includes it in AnalysisResponse.

## WO-037: User Story: WO-037 - Deny-by-default AuthzGuard with three-layer persona enforcement
- **Status:** completed
- **Commit:** `11d0f84`
- **Files:** 1 (+0/-0)
- **Duration:** 609ss
- **Approach:** N/A

## WO-040: User Story: WO-040 - Automated 90-Day Retention Purge Worker With Receipts
- **Status:** completed
- **Commit:** `5634e1a`
- **Files:** 13 (+1929/-1)
- **Duration:** 666ss
- **Approach:** Implemented WO-040 as a layered set of components: (1) Alembic migration 0009 adds purge_due_at + retention_class to pipeline_definition and status + error_detail to purge_receipt using batch_alter_table for SQLite/PostgreSQL compatibility. (2) PurgeRepository abstract interface + SQLAlchemyPurgeRepository implementation in persistence/repositories/purge.py handles advisory lock acquisition, due-definition selection (purge_due_at <= now, retention_class != 'sample'), FK-safe bulk deletes via delete() statements (generated_draft → remediation → finding → pipeline_definition → analysis), post-delete absence verification, receipt insertion, and SLA breach counting. (3) RetentionWorker in platform/retention/ is a framework-free class injected with PurgeRepository + AuditWriter; each batch runs in its own transaction, inserts one purge_receipt + one audit_event (action=retention.purge, actor_id=system:retention_worker), handles verification failures as status=failed receipts, and continues to subsequent batches on any per-batch error. (4) purge_receipt_builder.py computes SHA-256 digests over a strictly allowlisted manifest (ids, counts, timestamps only — no content). (5) ReconciliationService generates SLA breach counts. (6) CLI entry point at platform/retention/cli.py with --dry-run and --batch-size flags.

## WO-004: User Story: WO-004 - CI/CD format detection with user confirmation round-trip
- **Status:** completed
- **Commit:** `4ae221d`
- **Files:** 13 (+0/-0)
- **Duration:** 811ss
- **Approach:** N/A

## WO-012: User Story: WO-012 - Control Catalogue Admin Console UI
- **Status:** completed
- **Commit:** `e4717b6`
- **Files:** 26 (+2710/-0)
- **Duration:** 842ss
- **Approach:** Created a greenfield pipelineshield-web React 18 + TypeScript 5 strict-mode SPA using Vite. Implemented a pure catalogueReducer with six actions (stageCategoryWeight, toggleCategoryEnabled, stageControlSeverity, stageReferenceTools, resetStaged, rebaseAfterConflict) and three selectors (selectEnabledWeightTotal, selectDiff, selectCanSubmit). Components use Radix UI primitives for Dialog, Switch, and Select. TanStack Query handles data fetching with retry-on-5xx policy. MSW 2.x node server provides offline mock handlers for all API scenarios. Accessibility achieved via aria-live for weight total, aria-describedby for inline field errors, and Radix Dialog's built-in focus trap and Escape dismissal.

## WO-039: User Story: WO-039 - Role binding administration and IdP group persona mapping
- **Status:** completed
- **Commit:** `396c671`
- **Files:** 22 (+3139/-11)
- **Duration:** 853ss
- **Approach:** N/A

## WO-043: User Story: WO-043 - On-Demand Subject Data Export And Erasure
- **Status:** completed
- **Commit:** `40f2d0f`
- **Files:** 25 (+1449/-1)
- **Duration:** 588ss
- **Approach:** N/A

## WO-005: User Story: WO-005 - Upload and paste web experience with generated API types
- **Status:** completed
- **Commit:** `dfb653a`
- **Files:** 30 (+1920/-8)
- **Duration:** 961ss
- **Approach:** N/A

## WO-006: User Story: WO-006 - Versioned PipelineIR contract and GitHub Actions normalizer
- **Status:** completed
- **Commit:** `d277293`
- **Files:** 25 (+3022/-1)
- **Duration:** 1148ss
- **Approach:** Implemented the versioned PipelineIR contract and GitHub Actions normalizer. Core IR models (Anchor, ActionRef, SecretRef, Step, EffectivePermissions, Job, CoverageReport, PipelineIR) are frozen Pydantic v2 models in analysis/ir/pipeline_ir.py. The YAML loader uses ruamel.yaml in round-trip YAML 1.2 mode (y.version=(1,2)) to prevent YAML 1.1 boolean coercions (on: → True, NO → False) that would corrupt trigger analysis, plus a MAX_ALIASES=100 pre-check guard against anchor bombs. The GitHubActionsNormalizer handles scalar/list/mapping trigger forms, absent/empty/write_all/explicit permissions states, job steps with action ref parsing (sha/tag/branch/local/docker pin forms), secret ref extraction from ${{secrets.*}} and ${{env.*}} expressions, static matrix extraction, and marks composite/reusable workflow references as UnresolvedFragment (Not Assessable). Accessor helpers in accessors.py enforce the rule that security rules never access raw IR dict fields. NormalizationResult gained a pipeline_ir field and create_default_registry() factory pre-registers GitHubActionsNormalizer. Golden-file tests compare anchor-stripped IR dumps against expected/*.json; REGEN_GOLDEN=1 regenerates them.

## WO-007: User Story: WO-007 - GitLab CI normalizer with local-only include resolution
- **Status:** completed
- **Commit:** `8a8f6db`
- **Files:** 8 (+0/-0)
- **Duration:** 1221ss
- **Approach:** Implemented GitLabCINormalizer with two modules: gitlab_extends.py handles extends chain resolution (DFS cycle detection, deep-merge maps / replace-array semantics, topological sort), and gitlab_ci.py is the main normalizer. The !reference tag is registered once at module import via RoundTripConstructor.add_constructor and resolved post-load with flatten-in-sequence behaviour. Includes are classified into five kinds (local/remote/project/template/component); non-local and unresolvable-local includes are recorded as Not Assessable UnresolvedFragments and excluded from scoring. Hidden jobs (dot-prefix) participate in extends resolution but are excluded from the executable job list. Global default: block is merged into every job. Triggers are extracted from workflow.rules CI_PIPELINE_SOURCE expressions and job-level only/except. All IR fields map to the existing PipelineIR contract from WO-006 without GitLab-specific additions.

## WO-008: User Story: WO-008 - Jenkinsfile declarative-subset extractor with Not Assessable coverage
- **Status:** completed
- **Commit:** `005f81a`
- **Files:** 14 (+2319/-1)
- **Duration:** 1548ss
- **Approach:** N/A

## WO-042: User Story: WO-042 - Governance Console For Audit, Retention And Exports
- **Status:** completed
- **Commit:** `2eef4d9`
- **Files:** 11 (+997/-0)
- **Duration:** 538ss
- **Approach:** N/A

## WO-014: User Story: WO-014 - Deterministic Rule Engine Core Over Canonical PipelineIR
- **Status:** completed
- **Commit:** `c10d73a`
- **Files:** 6 (+0/-0)
- **Duration:** 536ss
- **Approach:** Built a framework-free, pure-Python rule evaluation runtime in a new analysis/rule_engine package. The engine accepts a canonical PipelineIR and a catalogue snapshot, iterates all registered rules in deterministic sorted order (by rule_id), applies per-rule try/except isolation, enforces node-count and wall-clock budget guards between rules, deduplicates by fingerprint, and returns a deterministically sorted EvaluationResult. No FastAPI, SQLAlchemy, HTTP client, or LLM imports exist in any engine module — verified by an import-graph test. Five IR fixtures cover all three CI formats plus empty and large (6200-node) cases.

## WO-015: User Story: WO-015 - Versioned Control Catalogue With Weighted Nine Categories
- **Status:** completed
- **Commit:** `ad80396`
- **Files:** 6 (+0/-0)
- **Duration:** 646ss
- **Approach:** Extended the existing WO-009 catalogue domain with the additional WO-015 requirements: ControlSource enum (deterministic/ai_advisory), weight_contribution field on ControlDefinition, CatalogueIntegrityError, two new CatalogueSnapshot validators (ai_advisory → weight_contribution=0; critical/high → non-empty reference_tools), a process-local CatalogueLoader with thread-safe cache and explicit invalidate(), and InMemoryCatalogueRepository satisfying the same abstract interface as the SQLAlchemy implementation. Updated catalogue_v1.json to add source/weight_contribution fields and fix the two high-severity controls (lp-001, ag-001) that had empty reference_tools.

## WO-016: User Story: WO-016 - High-Severity Pipeline Weakness Rule Pack Implementation
- **Status:** completed
- **Commit:** `415881e`
- **Files:** 20 (+1988/-0)
- **Duration:** 826ss
- **Approach:** N/A

## WO-017: User Story: WO-017 - Mandatory Anchor Validation Gate Suppressing Unanchored Findings
- **Status:** completed
- **Commit:** `060854c`
- **Files:** 16 (+0/-0)
- **Duration:** 539ss
- **Approach:** Created pipelineshield/analysis/anchoring/ package as the single chokepoint between candidate findings and persistence. RedactedDocument wraps an already-redacted RedactedDoc with a 1-based line index and per-line sha256 fingerprints (computed post-redaction). AnchorValidator.validate() runs a seven-step sequence (anchor present, bounds, unresolved-fragment, blank-line, fingerprint, snippet extraction, secret re-scan) returning ValidatedFinding objects and a SuppressionReport. FindingRepository.save_all() is added with a runtime isinstance guard that raises TypeError for any non-ValidatedFinding input and converts ValidatedFinding to Finding for persistence.

## WO-018: User Story: WO-018 - Control Coverage State Machine With Not-Assessable Accounting
- **Status:** completed
- **Commit:** `9579c8d`
- **Files:** 5 (+0/-0)
- **Duration:** 558ss
- **Approach:** Created pipelineshield/analysis/coverage/ package implementing a pure, stateless ControlEvaluator. The evaluator groups rule outcomes by control_id, applies an explicit 6-step state derivation policy (present/partial/missing/not_assessable) with documented precedence rules (resolved evidence dominates not_assessable), computes assessable_weight_total as the scoring denominator, maps IR UnresolvedFragment kinds to ExclusionReason enum values, deduplicates fragments by fragment_id (kind:locator), conditionally produces a BannerPayload, and emits metrics. Completeness and bounds invariants are asserted before returning.

## WO-019: User Story: WO-019 - Seeded Corpus Detection Benchmark Harness With Release Gate
- **Status:** completed
- **Commit:** `3d2d288`
- **Files:** 9 (+1569/-1)
- **Duration:** 925ss
- **Approach:** N/A

## WO-020: User Story: WO-020 - Deterministic weighted scoring engine with versioned catalogue
- **Status:** completed
- **Commit:** `97579c1`
- **Files:** 7 (+0/-0)
- **Duration:** 653ss
- **Approach:** Created pipelineshield/analysis/scoring/ package with a pure, stateless ScoringEngine (no FastAPI/SQLAlchemy imports) that consumes ControlVerdict list + CatalogueSnapshot and emits ScoreResult. Decimal ROUND_HALF_UP arithmetic for cross-platform reproducibility. NOT_ASSESSABLE controls excluded from both numerator and denominator. Category weight distributed equally among enabled controls when weight_contribution is zero. PARTIAL credit configurable per call (default 0.5). Zero denominator returns explicit unscorable result. Grade banding uses int comparison after ROUND_HALF_UP so 89.5 maps to A. Added AnalysisCategoryScore model, migration 0014, analysis.unscorable_reason column, and .importlinter config.

## WO-021: User Story: WO-021 - Assemble risk assessment report payload with mandatory disclaimer
- **Status:** completed
- **Commit:** `1cb7459`
- **Files:** 11 (+0/-0)
- **Duration:** 1017ss
- **Approach:** Defined AnalysisReport as a single Pydantic v2 model in api/v1/schemas/report.py with all required submodels. ReportService.build_report() composes score rows, category scores, findings, and coverage limitations into the validated report. Persona dispatch in the GET handler: app_developer uses get_by_id_owner_scoped; read:all personas use get_by_id — both return None→404. Advisory disclaimer enforced by field_validator that rejects blank/whitespace. CoverageLimitation model + migration 0015 adds coverage_limitation table and finding.control_id column. FindingRepository.save_all() now stores control_id from ValidatedFinding.

## WO-046: User Story: WO-046 - Detection Rate Benchmark Harness With Per-Format Gates
- **Status:** completed
- **Commit:** `9effbd4`
- **Files:** 3 (+165/-1)
- **Duration:** 890ss
- **Approach:** N/A

## WO-022: User Story: WO-022 - Anchor-validated AI explanation and why-it-matters pass
- **Status:** completed
- **Commit:** `58e8847`
- **Files:** 6 (+412/-0)
- **Duration:** 352ss
- **Approach:** N/A

## WO-024: User Story: WO-024 - Build report view with score, grade and coverage banner
- **Status:** completed
- **Commit:** `00d981d`
- **Files:** 7 (+165/-0)
- **Duration:** 427ss
- **Approach:** N/A

## WO-026: User Story: WO-026 - Recommended secure pipeline architecture engine
- **Status:** completed
- **Commit:** `9b94add`
- **Files:** 7 (+930/-0)
- **Duration:** 381ss
- **Approach:** N/A

## WO-031: User Story: WO-031 - Before and after pipeline comparison with projected score
- **Status:** completed
- **Commit:** `2c71f1a`
- **Files:** 7 (+0/-0)
- **Duration:** 275ss
- **Approach:** N/A

## WO-034: User Story: WO-034 - Findings export in JSON, SARIF and PDF with audit trail
- **Status:** completed
- **Commit:** `941bf37`
- **Files:** 0 (+0/-0)
- **Duration:** 63ss
- **Approach:** N/A

## WO-023: User Story: WO-023 - Resilient inference client with bounded timeout and circuit breaker
- **Status:** completed
- **Commit:** `485379f`
- **Files:** 2 (+134/-0)
- **Duration:** 177ss
- **Approach:** N/A

## WO-025: User Story: WO-025 - Build finding detail view with anchored evidence and remediation
- **Status:** completed
- **Commit:** `27a94dd`
- **Files:** 2 (+0/-0)
- **Duration:** 168ss
- **Approach:** N/A

## WO-027: User Story: WO-027 - Hardened draft configuration generator with review labelling
- **Status:** completed
- **Commit:** `286e1c2`
- **Files:** 0 (+0/-0)
- **Duration:** 139ss
- **Approach:** N/A

## WO-032: User Story: WO-032 - Seeded demonstration pipeline corpus with ground-truth manifest
- **Status:** completed
- **Commit:** `f381cac`
- **Files:** 2 (+187/-0)
- **Duration:** 158ss
- **Approach:** N/A

## WO-035: User Story: WO-035 - Accuracy benchmark harness as release-blocking quality gate
- **Status:** completed
- **Commit:** `7071ed0`
- **Files:** 1 (+186/-0)
- **Duration:** 250ss
- **Approach:** N/A

## WO-041: User Story: WO-041 - Enforce Confidential Classification And Secret Masking Everywhere
- **Status:** completed
- **Commit:** `a15ca27`
- **Files:** 1 (+0/-0)
- **Duration:** 68ss
- **Approach:** N/A

## WO-051: User Story: WO-051 - Private Beta Measurement Program And GA Sign-Off Gate
- **Status:** completed
- **Commit:** `39b0dac`
- **Files:** 5 (+1095/-0)
- **Duration:** 326ss
- **Approach:** N/A

## WO-028: User Story: WO-028 - Before-after diff and projected score API
- **Status:** completed
- **Commit:** `e6679fe`
- **Files:** 2 (+0/-0)
- **Duration:** 87ss
- **Approach:** N/A

## WO-048: User Story: WO-048 - Latency SLO Benchmark With OpenTelemetry Stage Instrumentation
- **Status:** completed
- **Commit:** `ad61c1e`
- **Files:** 4 (+857/-0)
- **Duration:** 262ss
- **Approach:** N/A

## WO-049: User Story: WO-049 - Secret Exposure Assertion Suite Across Logs Exports Errors
- **Status:** completed
- **Commit:** `fdb3222`
- **Files:** 6 (+93/-0)
- **Duration:** 135ss
- **Approach:** N/A

## WO-029: User Story: WO-029 - Secure architecture and draft config review UI
- **Status:** completed
- **Commit:** `c4910ef`
- **Files:** 1 (+0/-0)
- **Duration:** 212ss
- **Approach:** N/A

## WO-033: User Story: WO-033 - Guided end-to-end demo workflow across all personas
- **Status:** completed
- **Commit:** `2511045`
- **Files:** 0 (+0/-0)
- **Duration:** 88ss
- **Approach:** N/A
