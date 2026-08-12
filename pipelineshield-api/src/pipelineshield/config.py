"""Runtime configuration for PipelineShield.

All secrets are injected from environment variables.  The application refuses
to boot if any required secret reference is absent (fail-closed).  No secrets
may appear in source code or committed env files.
"""
from __future__ import annotations

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthConfig(BaseSettings):
    """OIDC and session configuration.

    Required variables (no defaults — service refuses to start if absent):
      OIDC_ISSUER            Issuer URL, e.g. https://login.example.com
      OIDC_CLIENT_ID         OAuth2 client_id registered with the IdP
      OIDC_CLIENT_SECRET     OAuth2 client_secret (secret — never logged)
      OIDC_REDIRECT_URI      Callback URI registered with the IdP
      REDIS_URL              redis[s]://host:port/db

    Optional tuning:
      OIDC_SCOPES            Space-separated scopes (default: openid email profile)
      SESSION_IDLE_TTL_SECONDS        Sliding idle timeout seconds (default: 1800)
      SESSION_ABSOLUTE_LIFETIME_SECONDS  Hard ceiling seconds (default: 28800)
      SESSION_ALLOWED_REDIRECT_PATHS  JSON list of allowed post-login paths
      OIDC_CLOCK_SKEW_SECONDS         id_token clock skew tolerance (default: 60)
      OIDC_JWKS_TTL_SECONDS           JWKS cache lifetime in seconds (default: 900)
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Required — no defaults
    oidc_issuer: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_redirect_uri: str
    redis_url: str

    # Optional tuning
    oidc_scopes: str = "openid email profile"
    session_idle_ttl_seconds: int = 1800
    session_absolute_lifetime_seconds: int = 28800
    session_allowed_redirect_paths: list[str] = Field(default_factory=lambda: ["/"])
    oidc_clock_skew_seconds: int = 60
    oidc_jwks_ttl_seconds: int = 900

    @field_validator("oidc_issuer")
    @classmethod
    def _issuer_must_be_https(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("oidc_issuer must use https://")
        return v.rstrip("/")

    @field_validator("oidc_redirect_uri")
    @classmethod
    def _redirect_uri_no_fragment(cls, v: str) -> str:
        if "#" in v:
            raise ValueError("oidc_redirect_uri must not contain a fragment")
        return v

    @field_validator("session_allowed_redirect_paths")
    @classmethod
    def _paths_must_be_relative(cls, paths: list[str]) -> list[str]:
        for path in paths:
            if not path.startswith("/") or "://" in path:
                raise ValueError(
                    f"Allowed redirect path {path!r} must be a relative path starting with /"
                )
        return paths
