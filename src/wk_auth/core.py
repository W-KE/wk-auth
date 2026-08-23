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

import logging
import uuid
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Response, status
from fastapi.responses import RedirectResponse
from fastapi_users import BaseUserManager, FastAPIUsers, UUIDIDMixin
from fastapi_users.authentication import AuthenticationBackend, CookieTransport
from fastapi_users.authentication.strategy.db import AccessTokenDatabase, DatabaseStrategy
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyAccessTokenDatabase
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from wk_auth.config import AuthSettings, OIDCSettings
from wk_auth.models import Role
from wk_auth.schemas import LoginMethods, SetupStatus, UserCreate, UserRead, UserUpdate
from wk_auth.secrets import SecretBox

SessionDependency = Callable[..., AsyncGenerator[AsyncSession, None]]

# The name embedded in fastapi-users' route names (oauth:{name}.{backend}.*)
# and in the mount path (see include_routers). Fixed rather than
# configurable: this package talks to exactly one kind of IdP.
OIDC_PROVIDER_NAME = "authentik"

_logger = logging.getLogger("wk_auth")


class _RedirectCookieTransport(CookieTransport):
    """A CookieTransport whose successful login is a redirect, not a 204.

    Used only for the OIDC callback. The IdP redirects the *browser* to
    that endpoint, so whatever it returns is what the user ends up looking
    at — and fastapi-users' CookieTransport hardcodes 204 No Content,
    which leaves them logged in but staring at a blank page at
    /api/auth/authentik/callback.

    Subclassing rather than post-processing keeps the cookie attributes
    (name, domain, secure, samesite, max-age) identical to the password
    login's, since `_set_login_cookie` is inherited untouched — the two
    routes must produce the same session cookie or one of them silently
    won't be honoured.
    """

    def __init__(self, *args, redirect_to: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.redirect_to = redirect_to

    async def get_login_response(self, token: str) -> Response:
        # 303: the callback arrives as a GET, and 303 tells the browser to
        # follow with a GET too, without offering to re-submit anything.
        response = RedirectResponse(self.redirect_to, status_code=status.HTTP_303_SEE_OTHER)
        return self._set_login_cookie(response, token)


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
    # None when no `oidc=` was passed to build_auth(), *or* when it was
    # passed but discovery against the IdP failed at startup — see
    # build_auth()'s docstring. Either way, local password login is
    # unaffected; only SSO is unavailable.
    oidc_router: APIRouter | None = None

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
        if self.oidc_router is not None:
            # -> {prefix}/auth/authentik/authorize, {prefix}/auth/authentik/callback
            app.include_router(
                self.oidc_router,
                prefix=f"{prefix}/auth/{OIDC_PROVIDER_NAME}",
                tags=["auth"],
            )

        oidc_on = self.oidc_router is not None
        authorize_url = f"{prefix}/auth/{OIDC_PROVIDER_NAME}/authorize" if oidc_on else None

        @app.get(f"{prefix}/auth/methods", response_model=LoginMethods, tags=["auth"])
        async def login_methods() -> LoginMethods:
            """What the login page should offer. Unauthenticated by
            necessity — it is read before anyone can be signed in."""
            return LoginMethods(
                password=True,
                oidc=oidc_on,
                oidc_name=OIDC_PROVIDER_NAME.title() if oidc_on else None,
                oidc_authorize_url=authorize_url,
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
    oauth_account_model: type | None = None,
    oidc: OIDCSettings | None = None,
) -> Auth:
    """Build an app's full auth stack.

    Pass `oidc=` (with `oauth_account_model=` — the app's own
    `OAuthAccount` class, built from `OAuthUserMixin` on its `User`) to add
    "log in with Authentik" alongside local password login. Local login
    never depends on it: if the IdP can't be reached when this function
    runs — which for most apps is once, at process startup — a warning is
    logged, `Auth.oidc_router` comes back `None`, and the app boots and
    serves local logins exactly as if `oidc` had been omitted. There is no
    retry; a later restart will attempt discovery again.

    That degrade-don't-block behaviour exists because OpenID Connect
    discovery is a **synchronous network call made by `OpenID.__init__`
    itself** (httpx-oauth's own design, not something this function can
    defer) — done naively, a moment of the IdP being unreachable would take
    the whole app down with it, including the local login this exists to
    keep as a fallback.
    """
    if oidc is not None and oauth_account_model is None:
        raise ValueError("build_auth(oidc=...) also requires oauth_account_model")

    async def get_user_db(
        session: AsyncSession = Depends(get_async_session),
    ) -> AsyncGenerator[Any, None]:
        yield SQLAlchemyUserDatabase(session, user_model, oauth_account_model)

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

    oidc_router = None
    if oidc is not None:
        # A backend of its own, differing from the password one *only* in
        # what a successful login returns: a redirect rather than 204. It
        # shares the strategy, so both routes mint the same kind of session,
        # and inherits the cookie attributes, so both set the same cookie.
        oidc_backend = AuthenticationBackend(
            name="cookie",
            transport=_RedirectCookieTransport(
                cookie_name=settings.cookie_name,
                cookie_max_age=settings.session_lifetime_seconds,
                cookie_domain=settings.cookie_domain,
                cookie_secure=settings.cookie_secure,
                cookie_samesite=settings.cookie_samesite,
                redirect_to=oidc.post_login_redirect,
            ),
            get_strategy=get_database_strategy,
        )
        oidc_router = _build_oidc_router(
            oidc=oidc,
            backend=oidc_backend,
            fastapi_users=fastapi_users,
            state_secret=settings.secret_key,
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
        oidc_router=oidc_router,
    )


def _build_oidc_router(
    *,
    oidc: OIDCSettings,
    backend: AuthenticationBackend,
    fastapi_users: FastAPIUsers,
    state_secret: str,
) -> APIRouter | None:
    """Discover the IdP and build its router — or, on any failure, log a
    warning and return None. See build_auth()'s docstring for why a
    failure here must not raise.
    """
    try:
        from httpx_oauth.clients.openid import OpenID
    except ImportError as exc:  # pragma: no cover - exercised by packaging, not logic
        raise ImportError(
            "build_auth(oidc=...) requires the 'oidc' extra: "
            'pip install "wk-auth[oidc]"'
        ) from exc

    try:
        client = OpenID(
            oidc.client_id, oidc.client_secret, oidc.discovery_url, name=OIDC_PROVIDER_NAME
        )
    except Exception as exc:  # noqa: BLE001 - any failure here degrades, never raises
        _logger.warning(
            "OIDC discovery against %s failed (%s: %s) — local password login is "
            "unaffected, but signing in via %s is unavailable until the next restart.",
            oidc.discovery_url,
            type(exc).__name__,
            exc,
            OIDC_PROVIDER_NAME,
        )
        return None

    return fastapi_users.get_oauth_router(
        client,
        backend,
        state_secret=state_secret,
        # See OIDCSettings' docstring for why this is safe specifically for
        # a self-hosted, operator-provisioned Authentik instance and not in
        # general.
        associate_by_email=True,
        is_verified_by_default=oidc.is_verified_by_default,
    )
