"""Builds an app's authentication stack.

Everything here is a factory rather than module-level state, because the
concrete `User` / `AccessToken` classes and the session dependency belong
to the app, not to this package. An app wires it up once:

    auth = build_auth(
        user_model=User,
        access_token_model=AccessToken,
        get_async_session=get_async_session,
        settings=AuthSettings(secret_key=settings.secret_key, ...),
    )

and then uses `auth.current_active_user`, `auth.require_admin`, and
`auth.include_routers(app)`.
"""
from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi_users import BaseUserManager, FastAPIUsers, UUIDIDMixin
from fastapi_users.authentication import AuthenticationBackend, CookieTransport
from fastapi_users.authentication.strategy.db import AccessTokenDatabase, DatabaseStrategy
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyAccessTokenDatabase
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from wk_auth.config import AuthSettings
from wk_auth.models import Role
from wk_auth.schemas import SetupStatus, UserCreate, UserRead, UserUpdate
from wk_auth.secrets import SecretBox

SessionDependency = Callable[..., AsyncGenerator[AsyncSession, None]]


@dataclass
class Auth:
    """The wired-up auth stack for one app."""

    settings: AuthSettings
    user_model: type
    access_token_model: type
    fastapi_users: FastAPIUsers
    backend: AuthenticationBackend
    get_user_manager: Callable
    current_active_user: Callable
    secrets: SecretBox
    setup_router: APIRouter

    def require_role(self, role: Role) -> Callable:
        """Dependency asserting the signed-in user holds `role`.

        Superusers always pass, so an admin never locks themselves out of
        their own instance by fiddling with roles.
        """

        def _check(user=Depends(self.current_active_user)):
            if user.role != role and not user.is_superuser:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, detail=f"requires role '{role.value}'"
                )
            return user

        return _check

    @property
    def require_admin(self) -> Callable:
        return self.require_role(Role.ADMIN)

    def include_routers(
        self,
        app: FastAPI,
        *,
        prefix: str = "/api",
        register: bool = True,
        setup: bool = True,
    ) -> None:
        """Mount the standard endpoints.

        `register=False` closes public sign-up for an instance where the
        admin creates every account by hand.
        """
        if setup:
            app.include_router(self.setup_router)
        app.include_router(
            self.fastapi_users.get_auth_router(self.backend),
            prefix=f"{prefix}/auth",
            tags=["auth"],
        )
        if register:
            app.include_router(
                self.fastapi_users.get_register_router(UserRead, UserCreate),
                prefix=f"{prefix}/auth",
                tags=["auth"],
            )
        app.include_router(
            self.fastapi_users.get_users_router(UserRead, UserUpdate),
            prefix=f"{prefix}/users",
            tags=["users"],
        )


def _build_setup_router(
    *,
    user_model: type,
    get_async_session: SessionDependency,
    get_user_manager: Callable,
    prefix: str,
) -> APIRouter:
    """First-run wizard: creates the initial admin, then locks itself.

    Once any user exists this returns 410 forever, so it can never be used
    to mint a second admin — that is what the admin user-management
    endpoints are for.
    """
    router = APIRouter(prefix=f"{prefix}/setup", tags=["setup"])

    @router.get("/status", response_model=SetupStatus)
    async def setup_status(
        session: AsyncSession = Depends(get_async_session),
    ) -> SetupStatus:
        count = (await session.execute(select(func.count()).select_from(user_model))).scalar_one()
        return SetupStatus(needs_setup=count == 0)

    @router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
    async def create_initial_admin(
        payload: UserCreate,
        session: AsyncSession = Depends(get_async_session),
        user_manager=Depends(get_user_manager),
    ):
        count = (await session.execute(select(func.count()).select_from(user_model))).scalar_one()
        if count > 0:
            raise HTTPException(status.HTTP_410_GONE, detail="setup already completed")

        user = await user_manager.create(payload)
        user.role = Role.ADMIN
        user.is_superuser = True
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    return router


def build_auth(
    *,
    user_model: type,
    access_token_model: type,
    get_async_session: SessionDependency,
    settings: AuthSettings,
    api_prefix: str = "/api",
) -> Auth:
    async def get_user_db(
        session: AsyncSession = Depends(get_async_session),
    ) -> AsyncGenerator[Any, None]:
        yield SQLAlchemyUserDatabase(session, user_model)

    async def get_access_token_db(
        session: AsyncSession = Depends(get_async_session),
    ) -> AsyncGenerator[AccessTokenDatabase, None]:
        yield SQLAlchemyAccessTokenDatabase(session, access_token_model)

    class UserManager(UUIDIDMixin, BaseUserManager[user_model, uuid.UUID]):  # type: ignore[valid-type]
        reset_password_token_secret = settings.secret_key
        verification_token_secret = settings.secret_key

    async def get_user_manager(user_db=Depends(get_user_db)) -> AsyncGenerator[UserManager, None]:
        yield UserManager(user_db)

    transport = CookieTransport(
        cookie_name=settings.cookie_name,
        cookie_max_age=settings.session_lifetime_seconds,
        cookie_domain=settings.cookie_domain,
        cookie_secure=settings.cookie_secure,
        cookie_samesite=settings.cookie_samesite,
    )

    def get_database_strategy(
        access_token_db: AccessTokenDatabase = Depends(get_access_token_db),
    ) -> DatabaseStrategy:
        return DatabaseStrategy(
            access_token_db, lifetime_seconds=settings.session_lifetime_seconds
        )

    backend = AuthenticationBackend(
        name="cookie", transport=transport, get_strategy=get_database_strategy
    )

    fastapi_users = FastAPIUsers[user_model, uuid.UUID](  # type: ignore[valid-type]
        get_user_manager, [backend]
    )

    return Auth(
        settings=settings,
        user_model=user_model,
        access_token_model=access_token_model,
        fastapi_users=fastapi_users,
        backend=backend,
        get_user_manager=get_user_manager,
        current_active_user=fastapi_users.current_user(active=True),
        secrets=SecretBox(settings.secret_key),
        setup_router=_build_setup_router(
            user_model=user_model,
            get_async_session=get_async_session,
            get_user_manager=get_user_manager,
            prefix=api_prefix,
        ),
    )
