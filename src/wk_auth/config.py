"""Auth configuration."""
from __future__ import annotations

from dataclasses import dataclass

DEFAULT_SESSION_LIFETIME = 60 * 60 * 24 * 30  # 30 days


@dataclass(frozen=True)
class AuthSettings:
    """Everything an app has to decide about its own sessions.

    `cookie_domain` is the hook for later single sign-on: leave it None and
    the cookie is scoped to the one host, set it to ".w-k.io" and a session
    created by any app is honoured by all of them — provided they also share
    `secret_key`, `cookie_name` and the access-token table.
    """

    secret_key: str

    cookie_name: str = "wk_session"
    cookie_domain: str | None = None
    # Must be True behind HTTPS and False on plain-HTTP localhost. A Secure
    # cookie over http:// is dropped by the browser with no error at all,
    # which presents as "clicking sign in does nothing".
    cookie_secure: bool = False
    cookie_samesite: str = "lax"
    session_lifetime_seconds: int = DEFAULT_SESSION_LIFETIME

    def __post_init__(self) -> None:
        if not self.secret_key or self.secret_key == "change-me-in-production":
            # Fail loudly at startup rather than silently shipping a
            # guessable session-signing and secret-encryption key.
            raise ValueError(
                "AuthSettings.secret_key must be set to a real secret "
                "(generate one with: python -c \"import secrets; "
                'print(secrets.token_urlsafe(48))")'
            )


@dataclass(frozen=True)
class OIDCSettings:
    """Wires an app up as a client of a shared IdP (Authentik) alongside
    its own local password login — SSO without giving up the fallback that
    keeps the app usable when the IdP is down or unreachable.

    ``associate_by_email`` (kept True — this is not exposed as False,
    see below) means: a successful OIDC login for an email that already
    has a local account gets *attached* to that account rather than
    rejected or duplicated. fastapi-users applies this purely by string
    match on the email the provider reports — it does not check an
    ``email_verified`` claim before linking. That is safe here because
    Authentik is the only OIDC source this package talks to, and every
    Authentik identity is hand-provisioned by the operator (no public
    self-registration) — there is no path for an outside party to mint an
    Authentik account claiming someone else's email. This stops being safe
    the moment self-service registration is enabled on the IdP, so treat
    that as a real precondition, not a formality.
    """

    client_id: str
    client_secret: str
    # e.g. "https://auth.w-k.io/application/o/<app-slug>/.well-known/openid-configuration"
    discovery_url: str
    # New accounts created via OIDC start verified: the IdP already
    # authenticated them, so there is nothing left for a local
    # verification e-mail to add.
    is_verified_by_default: bool = True

    def __post_init__(self) -> None:
        if not self.client_id or not self.client_secret:
            raise ValueError("OIDCSettings.client_id and .client_secret are required")
        if not self.discovery_url.startswith("https://"):
            raise ValueError(
                "OIDCSettings.discovery_url must be https:// — "
                f"got {self.discovery_url!r}"
            )
