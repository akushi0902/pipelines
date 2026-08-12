"""Catalogue API router — GET and PATCH /api/v1/catalogue.

The router is thin: it declares models, wires dependencies, and delegates
all business logic to CatalogueService.  No SQL and no role branching here.

Status code mapping
-------------------
200 GET success
201 PATCH success (new version created)
400 CatalogueValidationError (bad change set or weight total)
401 Missing or expired session (raised by get_current_actor stub)
403 AuthzGuard denial (persona lacks the required capability)
409 CatalogueVersionConflictError (stale base_version)
422 Pydantic validation failure (malformed payload)
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from pipelineshield.api.security.authz_guard import CurrentActor, require_capability
from pipelineshield.api.v1.schemas.catalogue import (
    CatalogueGetResponse,
    CataloguePatchRequest,
    CataloguePatchResponse,
    ErrorResponse,
    FieldError,
)
from pipelineshield.catalogue.schemas import (
    CatalogueValidationError,
    CatalogueVersionConflictError,
)
from pipelineshield.services.catalogue_service import (
    CatalogueNotFoundError,
    CatalogueService,
)

_LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/catalogue", tags=["catalogue"])

_service = CatalogueService()


# ---------------------------------------------------------------------------
# Database session dependency (overridden in tests via app.dependency_overrides)
# ---------------------------------------------------------------------------


def get_db() -> Session:  # pragma: no cover
    """Yield a SQLAlchemy session for the current request.

    The real implementation is wired via the FastAPI app factory.
    Tests override this dependency directly.
    """
    raise NotImplementedError("get_db must be overridden before use")


# ---------------------------------------------------------------------------
# GET /api/v1/catalogue
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=CatalogueGetResponse,
    summary="Get the active control catalogue",
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
)
async def get_catalogue(
    actor: Annotated[CurrentActor, Depends(require_capability("catalogue:read"))],
    session: Session = Depends(get_db),
) -> CatalogueGetResponse:
    try:
        return _service.get_active_catalogue(session)
    except CatalogueNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "type": "https://pipelineshield.internal/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": str(exc),
                "errors": [],
            },
        ) from exc


# ---------------------------------------------------------------------------
# PATCH /api/v1/catalogue
# ---------------------------------------------------------------------------


@router.patch(
    "",
    response_model=CataloguePatchResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new catalogue version",
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
async def patch_catalogue(
    request_body: CataloguePatchRequest,
    actor: Annotated[CurrentActor, Depends(require_capability("catalogue:write"))],
    session: Session = Depends(get_db),
) -> CataloguePatchResponse:
    try:
        return _service.apply_changes(session, actor, request_body)
    except CatalogueValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "type": "https://pipelineshield.internal/errors/validation",
                "title": "Catalogue Validation Error",
                "status": 400,
                "detail": str(exc),
                "errors": [{"field": exc.field, "message": str(exc)}]
                if exc.field
                else [],
            },
        ) from exc
    except CatalogueVersionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "type": "https://pipelineshield.internal/errors/conflict",
                "title": "Version Conflict",
                "status": 409,
                "detail": str(exc),
                "errors": [],
            },
        ) from exc
    except CatalogueNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "type": "https://pipelineshield.internal/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": str(exc),
                "errors": [],
            },
        ) from exc
