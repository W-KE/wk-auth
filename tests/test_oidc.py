"""OIDC ("log in with Authentik") tests.

Two things about httpx-oauth's own design shape these tests rather than
being incidental to them:

1. `OpenID.__init__` does a **synchronous** network call for discovery —
   there's no async or lazy option. That's exactly the failure mode
   build_auth() is written to survive (see its docstring), and the first
   two tests below exist to prove it actually does.
2. The token exchange and userinfo calls go through `get_httpx_client()`,
   a method on the shared `BaseOAuth2` class (which `OpenID` doesn't
   override) returning a fresh `httpx.AsyncClient()` per call. Patching
   that one method — not `httpx.AsyncClient` globally — wires in a fake
   Authentik without also intercepting the test's own ASGI-transport
   client that drives the FastAPI app itself.

Each test builds its own app on its own throwaway SQLite file via
`make_oidc_app()`, rather than sharing tests/conftest.py's engine: both
define a `User` model whose table name is hardcoded to "user" (matching
fastapi-users' own convention), so two independent metadata registries
racing to create/drop the same physical table would collide.
"""
from __future__ import annotations

import tempfile
import uuid
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

# `httpx_oauth.clients.openid.httpx` is the same module object as the
# global `httpx` — `import httpx` binds a name, it doesn't copy the
# module — so patching `...openid.httpx.Client` patches `httpx.Client`
# everywhere for the duration. A replacement lambda that itself calls
# `httpx.Client(...)` would therefore call *itself* once the patch is
# live, recursing into a TypeError instead of ever reaching a real
# client. Capturing the real class here, before any patching happens,
# and using that inside every replacement avoids the self-reference.
_RealClient = httpx.Client
_RealAsyncClient = httpx.AsyncClient

CLIENT_ID = "birdex-client-id"
CLIENT_SECRET = "birdex-client-secret"
DISCOVERY_URL = "https://auth.w-k.io/application/o/birdex/.well-known/openid-configuration"
DISCOVERY_DOC = {
    "issuer": "https://auth.w-k.io/application/o/birdex/",
    "authorization_endpoint": "https://auth.w-k.io/application/o/authorize/",
    "token_endpoint": "https://auth.w-k.io/application/o/token/",
    "userinfo_endpoint": "https://auth.w-k.io/application/o/userinfo/",
    "jwks_uri": "https://auth.w-k.io/application/o/birdex/jwks/",
    "scopes_supported": ["openid", "email", "profile"],
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


class FakeAuthentik:
    """Answers discovery (sync) and token+userinfo (async) for one
    configured identity, like a real Authentik instance would."""

    def __init__(self, *, sub: str = "authentik-sub-1", email: str = "ke@example.com"):
        self.sub = sub
        self.email = email
        self.token_requests: list[httpx.Request] = []
        self.userinfo_requests: list[httpx.Request] = []

    def sync_handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=DISCOVERY_DOC)
        return httpx.Response(404)

    async def async_handler(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_DOC["token_endpoint"]:
            self.token_requests.append(request)
            return httpx.Response(
                200,
                json={"access_token": "fake-access-token", "token_type": "bearer", "expires_in": 3600},
            )
        if str(request.url) == DISCOVERY_DOC["userinfo_endpoint"]:
            self.userinfo_requests.append(request)
            return httpx.Response(200, json={"sub": self.sub, "email": self.email})
        return httpx.Response(404, json={"error": "unhandled", "url": str(request.url)})


def patched(fake: FakeAuthentik) -> ExitStack:
    """Everything a FakeAuthentik needs patched in: sync discovery inside
    OpenID.__init__, and the async client every subsequent call goes
    through. Scope this around both app construction and the HTTP calls
    that drive /authorize and /callback."""
    stack = ExitStack()
    stack.enter_context(
        patch(
            "httpx_oauth.clients.openid.httpx.Client",
            lambda: _RealClient(transport=httpx.MockTransport(fake.sync_handler)),
        )
    )
    stack.enter_context(
        patch(
            "httpx_oauth.oauth2.BaseOAuth2.get_httpx_client",
            lambda self: _RealAsyncClient(transport=httpx.MockTransport(fake.async_handler)),
        )
    )
    return stack


class OidcApp:
    """A built app plus a handle on its own private database, so a test
    can both drive HTTP requests against it and query the database
    directly afterward (e.g. to assert no duplicate row was created)."""

    def __init__(self, app: FastAPI, session_maker: async_sessionmaker, user_model: type):
        self.app = app
        self.session_maker = session_maker
        self.user_model = user_model

    async def user_count(self) -> int:
        async with self.session_maker() as session:
            return (
                await session.execute(select(func.count()).select_from(self.user_model))
            ).scalar_one()


async def make_oidc_app(*, discovery_url: str = DISCOVERY_URL, require_account_model: bool = True) -> OidcApp:
    """Every call gets its own SQLite file and its own declarative Base —
    see the module docstring for why that isolation matters here."""
    from wk_auth import AccessTokenMixin, AuthSettings, OAuthAccountMixin, OAuthUserMixin, OIDCSettings, build_auth

    class Base(DeclarativeBase):
        pass

    class User(OAuthUserMixin, Base):
        pass

    class AccessToken(AccessTokenMixin, Base):
        pass

    class OAuthAccount(OAuthAccountMixin, Base):
        pass

    tmp = Path(tempfile.mkdtemp(prefix="wk-auth-oidc-"))
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp / f'{uuid.uuid4().hex}.db').as_posix()}")
    session_maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async def get_async_session():
        async with session_maker() as session:
            yield session

    auth = build_auth(
        user_model=User,
        access_token_model=AccessToken,
        get_async_session=get_async_session,
        settings=AuthSettings(secret_key="test-secret-key-not-for-production"),
        oauth_account_model=OAuthAccount if require_account_model else None,
        oidc=OIDCSettings(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, discovery_url=discovery_url),
    )

    app = FastAPI()
    auth.include_routers(app)
    app.state.auth = auth
    return OidcApp(app, session_maker, User)


async def _run_sso_login(client: AsyncClient, fake: FakeAuthentik) -> httpx.Response:
    """Drives /authorize -> (fake consent at Authentik) -> /callback, the
    same round trip a browser makes, reusing one client so the CSRF cookie
    /authorize sets travels through to /callback."""
    authorize = await client.get("/api/auth/authentik/authorize")
    assert authorize.status_code == 200, authorize.text
    state = httpx.URL(authorize.json()["authorization_url"]).params["state"]
    return await client.get("/api/auth/authentik/callback", params={"code": "fake-code", "state": state})


# --- discovery failure degrades instead of blocking startup ---------------


async def test_unreachable_idp_does_not_prevent_the_app_from_being_built():
    """The one behaviour this whole design exists for: a moment of
    Authentik being unreachable must not take local password login down
    with it."""

    def always_down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with patch(
        "httpx_oauth.clients.openid.httpx.Client",
        lambda: _RealClient(transport=httpx.MockTransport(always_down)),
    ):
        oidc_app = await make_oidc_app()

    assert oidc_app.app.state.auth.oidc_router is None


async def test_local_login_still_works_when_the_idp_was_unreachable_at_boot():
    def always_down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with patch(
        "httpx_oauth.clients.openid.httpx.Client",
        lambda: _RealClient(transport=httpx.MockTransport(always_down)),
    ):
        oidc_app = await make_oidc_app()

    async with AsyncClient(transport=ASGITransport(app=oidc_app.app), base_url="https://test") as client:
        res = await client.post(
            "/api/setup",
            json={"email": "admin@example.com", "password": "hunter22", "display_name": "Admin"},
        )
        assert res.status_code == 201, res.text

        login = await client.post(
            "/api/auth/login", data={"username": "admin@example.com", "password": "hunter22"}
        )
        assert login.status_code == 204

        # And the SSO route genuinely isn't mounted, rather than erroring.
        sso = await client.get("/api/auth/authentik/authorize")
        assert sso.status_code == 404


def test_oidc_requires_oauth_account_model():
    from wk_auth import AccessTokenMixin, AuthSettings, OAuthUserMixin, OIDCSettings, build_auth

    class Base(DeclarativeBase):
        pass

    class User(OAuthUserMixin, Base):
        pass

    class AccessToken(AccessTokenMixin, Base):
        pass

    with pytest.raises(ValueError, match="oauth_account_model"):
        build_auth(
            user_model=User,
            access_token_model=AccessToken,
            get_async_session=lambda: None,
            settings=AuthSettings(secret_key="test-secret-key-not-for-production"),
            oidc=OIDCSettings(client_id="x", client_secret="y", discovery_url=DISCOVERY_URL),
        )


# --- the actual SSO round trip ---------------------------------------------


async def test_a_new_identity_creates_an_account_and_logs_in():
    fake = FakeAuthentik(email="new-person@example.com")
    with patched(fake):
        oidc_app = await make_oidc_app()
        async with AsyncClient(transport=ASGITransport(app=oidc_app.app), base_url="https://test") as client:
            res = await _run_sso_login(client, fake)
            assert res.status_code == 204, res.text
            assert "wk_session" in client.cookies

            me = await client.get("/api/users/me")
            assert me.status_code == 200
            assert me.json()["email"] == "new-person@example.com"
            # Authentik already authenticated them; nothing left for a
            # local verification e-mail to add.
            assert me.json()["is_verified"] is True


async def test_oidc_login_links_to_an_existing_local_password_account():
    """associate_by_email: someone who already signed up with a password
    gets their Authentik identity *attached*, not duplicated."""
    fake = FakeAuthentik(email="ke@example.com")
    with patched(fake):
        oidc_app = await make_oidc_app()
        async with AsyncClient(transport=ASGITransport(app=oidc_app.app), base_url="https://test") as client:
            setup = await client.post(
                "/api/setup",
                json={"email": "ke@example.com", "password": "hunter22", "display_name": "Ke"},
            )
            assert setup.status_code == 201
            original_id = setup.json()["id"]

            res = await _run_sso_login(client, fake)
            assert res.status_code == 204, res.text

            me = await client.get("/api/users/me")
            assert me.json()["id"] == original_id  # same account, not a new one

    assert await oidc_app.user_count() == 1


async def test_linking_does_not_disturb_the_local_password():
    """OIDC is additive: after linking, the original password still works."""
    fake = FakeAuthentik(email="ke@example.com")
    with patched(fake):
        oidc_app = await make_oidc_app()
        async with AsyncClient(transport=ASGITransport(app=oidc_app.app), base_url="https://test") as client:
            await client.post(
                "/api/setup",
                json={"email": "ke@example.com", "password": "hunter22", "display_name": "Ke"},
            )
            await _run_sso_login(client, fake)
            await client.post("/api/auth/logout")

            login = await client.post(
                "/api/auth/login", data={"username": "ke@example.com", "password": "hunter22"}
            )
            assert login.status_code == 204


async def test_no_duplicate_account_is_created_on_a_second_sso_login():
    fake = FakeAuthentik(email="ke@example.com")
    with patched(fake):
        oidc_app = await make_oidc_app()
        async with AsyncClient(transport=ASGITransport(app=oidc_app.app), base_url="https://test") as client:
            await _run_sso_login(client, fake)
            await client.post("/api/auth/logout")
            await _run_sso_login(client, fake)

    assert await oidc_app.user_count() == 1
