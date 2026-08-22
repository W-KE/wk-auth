"""Model mixins.

These are mixins, not concrete tables, because each app owns its own
declarative ``Base``. An app applies them to its own Base:

    class User(UserMixin, Base):
        pass

    class AccessToken(AccessTokenMixin, Base):
        pass

and gets identical columns everywhere without this package having to know
about the app's metadata.
"""
from __future__ import annotations

import enum

from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyBaseAccessTokenTableUUID
from sqlalchemy import Enum
from sqlalchemy.orm import Mapped, mapped_column


class Role(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"


class UserMixin(SQLAlchemyBaseUserTableUUID):
    """fastapi-users' user table plus the fields every w-k.io app wants.

    ``is_superuser`` (from the base) is what fastapi-users' own checks look
    at; ``role`` is the app-level equivalent so permission dependencies
    don't have to special-case it. They are kept in sync wherever a role is
    assigned.
    """

    # Not "users": fastapi-users' access-token base hardcodes
    # ForeignKey("user.id"), so the table has to be called this. Pinning it
    # in the mixin stops an app from getting it wrong and only finding out
    # at first login.
    __tablename__ = "user"

    display_name: Mapped[str] = mapped_column(default="")
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.USER, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User id={self.id} email={self.email} role={self.role}>"


class AccessTokenMixin(SQLAlchemyBaseAccessTokenTableUUID):
    """Server-side session tokens.

    Sessions are stored rather than being stateless JWTs so that
    deactivating an account takes effect immediately instead of at token
    expiry.
    """

    __tablename__ = "access_tokens"
