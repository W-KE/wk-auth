# wk-auth

Shared authentication for self-hosted w-k.io apps (currently: [libra](../libra), [birdex](../birdex)).

Each app keeps its own database, its own `Base`, its own routers. This package supplies only what was previously copy-pasted between them and had already started to drift — literally: `libra`'s session cookie was missing `Secure`/`SameSite` while `birdex`'s had it, because the same code existed in two places and only one got fixed.

## What's in it

- `UserMixin` / `AccessTokenMixin` — apply to your own `Base` to get fastapi-users' tables plus `display_name` and `role`
- `GUID` / `UTCDateTime` — SQLAlchemy column types. `GUID` matches fastapi-users' own UUID serialization (dashed, not `.hex`) so a join between your tables and `user` doesn't silently return zero rows; `UTCDateTime` re-attaches the UTC offset SQLite drops, so timestamps don't get read as local time by the browser
- `build_auth(...)` — wires cookie-session auth (fastapi-users, DB-backed strategy) plus a self-locking first-run setup wizard
- `SecretBox` — Fernet encryption for secrets an app stores in its own DB (e.g. an Immich API key)

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

## What this does *not* do (yet)

Single sign-on. Two apps using this package each run their own independent login — same code, same cookie shape, but signing into one does not sign you into the other, because `cookie_domain` defaults to the current host and each app keeps its own `user`/`access_tokens` rows.

The path to real SSO is OIDC: point every app at a shared identity provider (Authentik) instead of having them check passwords against their own tables. `build_auth()`'s local login stays in place as a fallback for when the IdP is unreachable, which is also why the first-run setup wizard exists independent of any IdP.

## Local development

```bash
python -m venv .venv
.venv/Scripts/activate  # or source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Versioning

Not yet published anywhere — apps pin it via a local path or a git dependency:

```toml
dependencies = [
    "wk-auth @ git+https://github.com/W-KE/wk-auth@main",
]
```

No stability promises yet; both consumers (libra, birdex) are maintained by the same person who maintains this package, so a breaking change here is made together with the call sites that need updating.
