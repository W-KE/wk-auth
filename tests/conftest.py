"""A minimal FastAPI app wired with wk_auth, standing in for a real one.

Mirrors what birdex/libra actually do: their own Base, their own User/
AccessToken tables via the mixins, their own session, wk_auth wiring on top.
If this harness works, the real apps' wiring works the same way.
"""
from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncGenerator
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="wk-auth-tests-"))
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")

import pytest  # noqa: E402
from asgi_lifespan import LifespanManager  # noqa: E402
from fastapi import Depends, FastAPI  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.orm import DeclarativeBase  # noqa: E402

from wk_auth import AccessTokenMixin, AuthSettings, UserMixin, build_auth  # noqa: E402


class Base(DeclarativeBase):
    pass


class User(UserMixin, Base):
    pass


class AccessToken(AccessTokenMixin, Base):
    pass


engine = create_async_engine(f"sqlite+aiosqlite:///{(_tmp / 'test.db').as_posix()}")
async_session_maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session


def make_app(**settings_kwargs) -> FastAPI:
    auth = build_auth(
        user_model=User,
        access_token_model=AccessToken,
        get_async_session=get_async_session,
        settings=AuthSettings(secret_key=os.environ["SECRET_KEY"], **settings_kwargs),
    )

    app = FastAPI()
    auth.include_routers(app)

    @app.get("/api/whoami")
    async def whoami(user: User = Depends(auth.current_active_user)):
        return {"email": user.email, "role": user.role.value}

    @app.get("/api/admin-only")
    async def admin_only(user: User = Depends(auth.require_admin)):
        return {"ok": True}

    app.state.auth = auth
    return app


@pytest.fixture(autouse=True)
async def clean_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest.fixture
async def client():
    app = make_app()
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c


@pytest.fixture
async def admin_client(client: AsyncClient) -> AsyncClient:
    await client.post(
        "/api/setup",
        json={"email": "admin@example.com", "password": "hunter22", "display_name": "Admin"},
    )
    await client.post(
        "/api/auth/login", data={"username": "admin@example.com", "password": "hunter22"}
    )
    return client
