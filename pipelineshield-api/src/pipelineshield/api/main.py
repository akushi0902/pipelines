"""FastAPI application factory for PipelineShield API.

The app is created via `create_app()` so that tests can override
dependencies (session, current actor) without mutating global state.
"""

from __future__ import annotations

import logging
import os
import secrets as _secrets
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from pipelineshield.api.middleware.body_size_limit import BodySizeLimitMiddleware
from pipelineshield.api.security.authz_guard import (
    CurrentActor,
    get_current_actor,
)
from pipelineshield.api.security.scope import (
    AuthorizationError,
    ResourceNotVisibleError,
)
from pipelineshield.api.v1.routers import admin_router as _admin_mod
from pipelineshield.api.v1.routers import analysis_router as _analysis_mod
from pipelineshield.api.v1.routers import audit_router as _audit_mod
from pipelineshield.api.v1.routers import auth_router as _auth_mod
from pipelineshield.api.v1.routers import catalogue_router as _catalogue_mod
from pipelineshield.api.v1.routers import governance_router as _governance_mod

from pipelineshield.api.v1.routers.admin_router import router as admin_router
from pipelineshield.api.v1.routers.analysis_router import router as analysis_router
from pipelineshield.api.v1.routers.audit_router import router as audit_router
from pipelineshield.api.v1.routers.auth_router import router as auth_router
from pipelineshield.api.v1.routers.catalogue_router import router as catalogue_router
from pipelineshield.api.v1.routers.governance_router import router as governance_router

_LOG_MAIN = logging.getLogger(__name__)


def create_app() -> FastAPI:
    app = FastAPI(
        title="PipelineShield API",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # ------------------------------------------------------------------
    # Middleware
    # ------------------------------------------------------------------

    app.add_middleware(BodySizeLimitMiddleware)

    # ------------------------------------------------------------------
    # Routers
    # ------------------------------------------------------------------

    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(catalogue_router, prefix="/api/v1")
    app.include_router(audit_router, prefix="/api/v1")
    app.include_router(analysis_router, prefix="/api/v1")
    app.include_router(admin_router, prefix="/api/v1")
    app.include_router(governance_router, prefix="/api/v1")

    # ------------------------------------------------------------------
    # DEV-ONLY AUTH BYPASS
    # ------------------------------------------------------------------

    if os.getenv("DISABLE_AUTH", "false").lower() == "true":

        async def _dev_actor() -> CurrentActor:
            return CurrentActor(
                user_id=uuid.UUID(
                    "00000000-0000-0000-0001-000000000005"
                ),
                persona="appsec_lead",
                workspace_id=uuid.UUID(
                    "00000000-0000-0000-0000-000000000001"
                ),
                display_name="Dev User (auth disabled)",
            )

        app.dependency_overrides[get_current_actor] = _dev_actor

    # ------------------------------------------------------------------
    # DATABASE SESSION WIRING
    # ------------------------------------------------------------------

    if os.getenv("DATABASE_URL"):

        from pipelineshield.persistence.db import (
            create_engine_from_env,
            make_session_factory,
        )

        _engine = create_engine_from_env()
        _SessionLocal = make_session_factory(_engine)

        def _get_db_session():
            db = _SessionLocal()

            try:
                yield db
                db.commit()

            except Exception:
                db.rollback()
                raise

            finally:
                db.close()

        for _module in (
            _auth_mod,
            _catalogue_mod,
            _audit_mod,
            _analysis_mod,
            _admin_mod,
            _governance_mod,
        ):
            app.dependency_overrides[_module.get_db] = _get_db_session

        # --------------------------------------------------------------
        # RULE ENGINE WIRING
        # --------------------------------------------------------------
        #
        # This is the missing piece causing:
        #
        # RuntimeError:
        # RuleEngine is not configured.
        #
        # Build the default registry once at application startup and
        # inject the RuleEngine into the analysis router's orchestrator.
        # --------------------------------------------------------------

        from pipelineshield.analysis.rule_engine.engine import RuleEngine
        from pipelineshield.analysis.rules import build_default_registry
        from pipelineshield.crypto.key_provider import EnvKeyProvider
        from pipelineshield.services.analysis_orchestrator import (
            AnalysisOrchestrator,
        )

        _rule_registry = build_default_registry()
        _rule_engine = RuleEngine(
            registry=_rule_registry,
        )

        def _get_orchestrator() -> AnalysisOrchestrator:
            return AnalysisOrchestrator(
                key_provider=EnvKeyProvider(),
                rule_engine=_rule_engine,
            )

        app.dependency_overrides[
            _analysis_mod.get_orchestrator
        ] = _get_orchestrator

        _LOG_MAIN.info(
            "analysis_rule_engine_configured rule_count=%d",
            len(_rule_registry),
        )

        # --------------------------------------------------------------
        # OPTIONAL DEMO SEED
        # --------------------------------------------------------------

        if os.getenv("SEED_DEMO_DATA", "false").lower() == "true":

            @app.on_event("startup")
            def _seed_demo_data() -> None:  # pragma: no cover
                from tests.fixtures.seed_baseline import seed_baseline
                from pipelineshield.catalogue.seed import seed_v1_catalogue

                db = _SessionLocal()

                try:
                    ids = seed_baseline(db)

                    seed_v1_catalogue(
                        db,
                        created_by=ids["user_ids"]["appsec_lead"],
                    )

                    db.commit()

                    _LOG_MAIN.info(
                        "demo_seed_complete"
                    )

                except Exception:
                    db.rollback()

                    _LOG_MAIN.exception(
                        "demo_seed_failed"
                    )

                    raise

                finally:
                    db.close()

    # ------------------------------------------------------------------
    # RFC 7807 — AuthorizationError
    # ------------------------------------------------------------------

    @app.exception_handler(AuthorizationError)
    async def _authz_error_handler(
        request: Request,
        exc: AuthorizationError,
    ) -> JSONResponse:

        corr = _secrets.token_hex(16)

        return JSONResponse(
            status_code=403,
            content={
                "type": (
                    "https://pipelineshield.internal/"
                    "errors/forbidden"
                ),
                "title": "Forbidden",
                "status": 403,
                "detail": str(exc),
                "correlation_id": corr,
                "required_capability": exc.required_capability,
                "errors": [],
            },
        )

    # ------------------------------------------------------------------
    # RFC 7807 — ResourceNotVisibleError
    # ------------------------------------------------------------------

    @app.exception_handler(ResourceNotVisibleError)
    async def _not_visible_handler(
        request: Request,
        exc: ResourceNotVisibleError,
    ) -> JSONResponse:

        corr = _secrets.token_hex(16)

        return JSONResponse(
            status_code=404,
            content={
                "type": (
                    "https://pipelineshield.internal/"
                    "errors/not-found"
                ),
                "title": "Not Found",
                "status": 404,
                "detail": (
                    f"The requested "
                    f"{exc.resource_type} was not found."
                ),
                "correlation_id": corr,
                "errors": [],
            },
        )

    # ------------------------------------------------------------------
    # RFC 7807 — Validation Error
    # ------------------------------------------------------------------

    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:

        corr = _secrets.token_hex(16)

        errors = exc.errors()

        return JSONResponse(
            status_code=422,
            content={
                "type": (
                    "https://pipelineshield.internal/"
                    "errors/validation-error"
                ),
                "title": "Validation Error",
                "status": 422,
                "detail": (
                    "Request body failed schema validation."
                ),
                "correlation_id": corr,
                "errors": [
                    {
                        "field": ".".join(
                            str(value)
                            for value in e.get("loc", [])
                        ),
                        "message": e.get("msg", ""),
                    }
                    for e in errors
                ],
            },
        )

    return app


app = create_app()
