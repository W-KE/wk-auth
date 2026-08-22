"""Behaviour every app wired with build_auth() depends on."""
from __future__ import annotations

from httpx import AsyncClient

from tests.conftest import make_app


async def test_setup_creates_admin_then_locks_itself(client: AsyncClient):
    assert (await client.get("/api/setup/status")).json() == {"needs_setup": True}

    res = await client.post(
        "/api/setup",
        json={"email": "admin@example.com", "password": "hunter22", "display_name": "Ke"},
    )
    assert res.status_code == 201, res.text
    assert res.json()["role"] == "admin"

    assert (await client.get("/api/setup/status")).json() == {"needs_setup": False}

    # A second call must never be able to mint another admin.
    res = await client.post(
        "/api/setup",
        json={"email": "sneaky@example.com", "password": "hunter22", "display_name": "Nope"},
    )
    assert res.status_code == 410


async def test_login_sets_session_cookie_scoped_to_the_configured_name(admin_client: AsyncClient):
    assert "wk_session" in admin_client.cookies

    res = await admin_client.get("/api/whoami")
    assert res.status_code == 200
    assert res.json() == {"email": "admin@example.com", "role": "admin"}


async def test_unauthenticated_requests_are_rejected(client: AsyncClient):
    assert (await client.get("/api/whoami")).status_code == 401


async def test_require_admin_rejects_a_plain_user(admin_client: AsyncClient):
    await admin_client.post(
        "/api/auth/register",
        json={"email": "family@example.com", "password": "hunter22", "display_name": "Family"},
    )
    await admin_client.post("/api/auth/logout")
    await admin_client.post(
        "/api/auth/login", data={"username": "family@example.com", "password": "hunter22"}
    )

    assert (await admin_client.get("/api/admin-only")).status_code == 403


async def test_require_admin_accepts_the_admin(admin_client: AsyncClient):
    assert (await admin_client.get("/api/admin-only")).status_code == 200


async def test_register_false_closes_public_signup():
    from asgi_lifespan import LifespanManager
    from fastapi import FastAPI
    from httpx import ASGITransport

    from tests.conftest import get_async_session
    from wk_auth import AuthSettings, build_auth
    from tests.conftest import AccessToken, User

    auth = build_auth(
        user_model=User,
        access_token_model=AccessToken,
        get_async_session=get_async_session,
        settings=AuthSettings(secret_key="test-secret-key-not-for-production"),
    )
    app = FastAPI()
    auth.include_routers(app, register=False)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            res = await c.post(
                "/api/auth/register",
                json={"email": "x@example.com", "password": "hunter22"},
            )
            assert res.status_code == 404


async def test_secret_key_default_is_rejected():
    """A shared package is exactly where a copy-pasted placeholder secret
    would quietly ship to every app that used it — refuse at startup."""
    import pytest

    from wk_auth import AuthSettings

    with pytest.raises(ValueError, match="secret_key"):
        AuthSettings(secret_key="change-me-in-production")

    with pytest.raises(ValueError, match="secret_key"):
        AuthSettings(secret_key="")


async def test_cookie_name_is_configurable_per_app():
    """Two apps sharing a browser must not collide on the session cookie."""
    app = make_app(cookie_name="totally-different-cookie")
    from asgi_lifespan import LifespanManager
    from httpx import ASGITransport

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/setup",
                json={"email": "a@example.com", "password": "hunter22", "display_name": "A"},
            )
            await c.post(
                "/api/auth/login", data={"username": "a@example.com", "password": "hunter22"}
            )
            assert "totally-different-cookie" in c.cookies
            assert "wk_session" not in c.cookies
