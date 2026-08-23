"""fastapi-users read/create/update schemas, extended with our fields."""
from __future__ import annotations

import uuid

from fastapi_users import schemas
from pydantic import BaseModel

from wk_auth.models import Role


class UserRead(schemas.BaseUser[uuid.UUID]):
    display_name: str
    role: Role


class UserCreate(schemas.BaseUserCreate):
    display_name: str = ""
    # `role` is deliberately NOT accepted here — registration always creates
    # a plain user. Only the first-run setup wizard or an existing admin can
    # grant admin.


class UserUpdate(schemas.BaseUserUpdate):
    display_name: str | None = None


class SetRoleRequest(BaseModel):
    role: Role


class SetupStatus(BaseModel):
    needs_setup: bool


class LoginMethods(BaseModel):
    """Which ways in this deployment actually offers.

    Read by the login page *before* anyone is signed in, so it must be
    unauthenticated — it therefore says only whether a method is on, never
    anything about how it's configured.

    Without this a login page has no way to know whether to draw an SSO
    button: OIDC is optional per-deployment and, even when configured, is
    dropped if the IdP was unreachable at startup (see build_auth). A
    hardcoded button would 404 for exactly the people who most need the
    password form to work.
    """

    password: bool = True
    oidc: bool = False
    # Label for the button, and where it points. Both null when oidc is False.
    oidc_name: str | None = None
    oidc_authorize_url: str | None = None
