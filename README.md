# wk-auth

Shared authentication for self-hosted w-k.io apps (currently: [libra](../libra), [birdex](../birdex)).

Each app keeps its own database, its own `Base`, its own routers. This package supplies only what was previously copy-pasted between them and had already started to drift — literally: `libra`'s session cookie was missing `Secure`/`SameSite` while `birdex`'s had it, because the same code existed in two places and only one got fixed.

## What's in it

- `UserMixin` / `AccessTokenMixin` — apply to your own `Base` to get fastapi-users' tables plus `display_name` and `role`
- `GUID` / `UTCDateTime` — SQLAlchemy column types. `GUID` matches fastapi-users' own UUID serialization (dashed, not `.hex`) so a join between your tables and `user` doesn't silently return zero rows; `UTCDateTime` re-attaches the UTC offset SQLite drops, so timestamps don't get read as local time by the browser
- `build_auth(...)` — wires cookie-session auth (fastapi-users, DB-backed strategy) plus a self-locking first-run setup wizard
- `SecretBox` — Fernet encryption for secrets an app stores in its own DB (e.g. an Immich API key)
- `OAuthUserMixin` / `OAuthAccountMixin` / `OIDCSettings` — "log in with Authentik" alongside local password login (needs the `oidc` extra: `pip install "wk-auth[oidc]"`)
- `GET {prefix}/auth/methods` — mounted automatically; tells a login page which methods to offer, so it can draw an SSO button only when SSO actually works

## Wiring it into an app

```python
from wk_auth import AuthSettings, UserMixin, AccessTokenMixin, build_auth

class User(UserMixin, Base):
    pass

class AccessToken(AccessTokenMixin, Base):
    pass

auth = build_auth(
    user_model=User,
    access_token_model=AccessToken,
    get_async_session=get_async_session,
    settings=AuthSettings(
        secret_key=settings.secret_key,
        cookie_name="birdex_session",   # must differ between apps sharing a browser
        cookie_secure=settings.cookie_secure,
    ),
)
auth.include_routers(app)  # mounts /api/setup, /api/auth/*, /api/users/*

# in a router:
@router.get("/whatever")
async def handler(user: User = Depends(auth.current_active_user)):
    ...

router = APIRouter(dependencies=[Depends(auth.require_admin)])
```

Run `alembic revision --autogenerate` after adding the mixins — the tables live in your app's own migrations, this package owns no schema of its own.

## Adding "log in with Authentik"

```python
from wk_auth import AuthSettings, OAuthUserMixin, OAuthAccountMixin, OIDCSettings, build_auth

class User(OAuthUserMixin, Base):     # instead of UserMixin
    pass

class OAuthAccount(OAuthAccountMixin, Base):  # name must be exactly this
    pass

auth = build_auth(
    user_model=User,
    access_token_model=AccessToken,
    get_async_session=get_async_session,
    settings=AuthSettings(secret_key=settings.secret_key, cookie_name="birdex_session"),
    oauth_account_model=OAuthAccount,
    oidc=OIDCSettings(
        client_id=...,      # from Authentik's Provider config
        client_secret=...,
        discovery_url="https://auth.w-k.io/application/o/<app-slug>/.well-known/openid-configuration",
    ),
)
auth.include_routers(app)  # + mounts /api/auth/authentik/{authorize,callback}
```

A successful SSO login answers with a **303 redirect** to `post_login_redirect` (default `/`), not the 204 that password login returns — the IdP redirects the *browser* to the callback, so its response is the page the user lands on, and a 204 would leave them logged in but staring at a blank screen. Both routes set an identical session cookie.

Local login is never at the IdP's mercy: `OpenID.__init__` (httpx-oauth's own class, not something wired around here) does its discovery call **synchronously at construction time** — if that fails, `build_auth()` logs a warning and returns with `auth.oidc_router is None`, and the rest of the app — including local password login and the setup wizard — boots exactly as if `oidc=` had been omitted. There's no retry; the next process restart tries discovery again. `tests/test_oidc.py` asserts this directly (an unreachable IdP still lets local login work end to end).

A successful Authentik login is linked to an existing local account by e-mail match (`associate_by_email=True`, not exposed as configurable — see `OIDCSettings`' docstring for why that's safe specifically for a self-hosted, operator-provisioned IdP with no public registration, and stops being safe the moment that changes).

Full walkthrough for standing up Authentik itself, including the per-app Provider/Application recipe: see `../homelab-authentik/SETUP.md`.

## What this does *not* do (yet)

True single sign-on *between apps that don't share an IdP login*. Once every app is wired to the same Authentik instance (above), signing into Authentik once and visiting a second app still requires that app's own `/authorize` round trip — Authentik itself remembers the browser is already authenticated and skips re-prompting for a password, but each app still gets its own local session cookie via its own callback. That's normal OIDC behaviour, not a gap here.

What's still genuinely missing: apps don't share a session *cookie* — `cookie_domain` defaults to the current host, and each app keeps its own `user`/`access_tokens` rows regardless of whether OIDC is wired up, linked by e-mail rather than by a shared user table.

## Local development

```bash
python -m venv .venv
.venv/Scripts/activate  # or source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Versioning

Not published to PyPI. Apps depend on it by git URL, **pinned to a tag**:

```toml
dependencies = [
    "wk-auth[oidc] @ git+https://github.com/W-KE/wk-auth@v0.3.0",
]
```

Pinned rather than tracking `@master`, so that rebuilding an app image a
month from now produces the same `wk_auth` it did today. With `@master`
an app's image content depends on when it happened to be built, which
makes "worked yesterday, broken today" impossible to attribute.

### Cutting a release

1. Bump `version` in `pyproject.toml`.
2. Commit, then `git tag vX.Y.Z && git push origin master --tags`.
3. Bump the tag in each consumer's `pyproject.toml` (`birdex`, `libra`)
   and reinstall — `pip install -e .` won't re-resolve a git URL that
   hasn't changed, so a *new* tag is what makes consumers pick it up.

Consumers stay on their pinned tag until step 3, which is the point: a
change here can't silently reach a running app.

No stability promises yet; both consumers are maintained by the same
person who maintains this package, so a breaking change here is made
together with the call sites that need updating.
