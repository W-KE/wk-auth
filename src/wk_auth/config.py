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
