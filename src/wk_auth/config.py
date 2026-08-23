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
    # Where the browser lands after a successful SSO login. The IdP
    # redirects the *browser* to the callback endpoint, so its response is
    # what the user sees — without a redirect they end up on a blank page
    # (fastapi-users answers a successful login with 204 No Content).
    # Defaults to the app root, which for an SPA is the right place.
    post_login_redirect: str = "/"
    # New accounts created via OIDC start verified: the IdP already
    # authenticated them, so there is nothing left for a local
    # verification e-mail to add.
    is_verified_by_default: bool = True

    # Name of the IdP group whose members get the admin role, e.g.
    # "birdex-admins". Left None, OIDC never touches anyone's role and the
    # only admin is whoever the first-run wizard created.
    #
    # Set it and the IdP becomes authoritative on *every* OIDC login:
    # members are promoted, non-members are demoted. Demotion is the point
    # — without it, removing someone from the group in Authentik would
    # leave their admin rights here forever. Two accounts are exempt, both
    # to keep a lockout from being one config typo away: superusers (the
    # first-run account), and the last remaining admin.
    admin_group: str | None = None
    # Authentik ships groups in the `groups` claim of the profile scope.
    groups_claim: str = "groups"

    def __post_init__(self) -> None:
        if not self.client_id or not self.client_secret:
            raise ValueError("OIDCSettings.client_id and .client_secret are required")
        if not _is_https_or_loopback(self.discovery_url):
            # A malformed URL is a typo in your own config, so it's raised
            # rather than degraded — unlike an IdP that's merely
            # unreachable, which build_auth() survives. The distinction is
            # deliberate: an outage is transient and shouldn't take local
            # password login down with it, while a typo needs fixing and
            # would otherwise sit silently disabled.
            raise ValueError(
                "OIDCSettings.discovery_url must be https:// (http:// is "
                "allowed only for loopback addresses during local "
                f"development) — got {self.discovery_url!r}"
            )


# Plain http would put the client_secret and the authorization code on the
# wire in clear, so it's refused — except on loopback, where the traffic
# never leaves the machine and requiring TLS would mean nobody can
# exercise the SSO flow locally without provisioning certificates.
_LOOPBACK_PREFIXES = (
    "http://127.0.0.1",
    "http://[::1]",
    "http://localhost",
)


def _is_https_or_loopback(url: str) -> bool:
    if url.startswith("https://"):
        return True
    return any(
        url == prefix or url.startswith(prefix + "/") or url.startswith(prefix + ":")
        for prefix in _LOOPBACK_PREFIXES
    )
