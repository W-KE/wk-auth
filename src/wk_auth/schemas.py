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
