"""Shared authentication for self-hosted w-k.io apps.

Each app keeps its own database and its own declarative Base; this package
supplies the pieces that were otherwise copy-pasted between them and had
already started to drift apart.

Typical wiring:

    from wk_auth import AuthSettings, UserMixin, AccessTokenMixin, build_auth

    class User(UserMixin, Base): pass
    class AccessToken(AccessTokenMixin, Base): pass

    auth = build_auth(
        user_model=User,
        access_token_model=AccessToken,
        get_async_session=get_async_session,
        settings=AuthSettings(
            secret_key=settings.secret_key,
            cookie_name="birdex_session",
            cookie_secure=settings.cookie_secure,
        ),
    )
    auth.include_routers(app)
"""
from wk_auth.config import DEFAULT_SESSION_LIFETIME, AuthSettings
from wk_auth.core import Auth, build_auth
from wk_auth.models import AccessTokenMixin, Role, UserMixin
from wk_auth.schemas import (
    SetRoleRequest,
    SetupStatus,
    UserCreate,
    UserRead,
    UserUpdate,
)
from wk_auth.secrets import SecretBox
from wk_auth.types import GUID, UTCDateTime

__all__ = [
    "GUID",
    "UTCDateTime",
    "AccessTokenMixin",
    "Auth",
    "AuthSettings",
    "DEFAULT_SESSION_LIFETIME",
    "Role",
    "SecretBox",
    "SetRoleRequest",
    "SetupStatus",
    "UserCreate",
    "UserMixin",
    "UserRead",
    "UserUpdate",
    "build_auth",
]
