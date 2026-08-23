"""OIDCSettings / AuthSettings validation."""
from __future__ import annotations

import pytest

from wk_auth import AuthSettings, OIDCSettings


def _oidc(url: str) -> OIDCSettings:
    return OIDCSettings(client_id="id", client_secret="secret", discovery_url=url)


@pytest.mark.parametrize(
    "url",
    [
        "https://auth.w-k.io/application/o/birdex/.well-known/openid-configuration",
        # Loopback over plain http: the traffic never leaves the machine,
        # and requiring TLS here would mean the SSO flow can't be exercised
        # locally without provisioning certificates.
        "http://127.0.0.1:9600/application/o/birdex/.well-known/openid-configuration",
        "http://localhost:9600/.well-known/openid-configuration",
        "http://[::1]:9600/.well-known/openid-configuration",
    ],
)
def test_accepted_discovery_urls(url: str):
    assert _oidc(url).discovery_url == url


@pytest.mark.parametrize(
    "url",
    [
        # Plain http off-machine would put the client secret and the
        # authorization code on the wire in clear.
        "http://auth.w-k.io/.well-known/openid-configuration",
        # Not loopback despite the prefix — these are real routable hosts.
        "http://localhost.evil.com/.well-known/openid-configuration",
        "http://127.0.0.1.evil.com/.well-known/openid-configuration",
        "ftp://auth.w-k.io/",
        "auth.w-k.io/.well-known/openid-configuration",
    ],
)
def test_rejected_discovery_urls(url: str):
    with pytest.raises(ValueError, match="https"):
        _oidc(url)


def test_client_credentials_are_required():
    with pytest.raises(ValueError, match="client_id"):
        OIDCSettings(client_id="", client_secret="s", discovery_url="https://a/b")
    with pytest.raises(ValueError, match="client_secret"):
        OIDCSettings(client_id="i", client_secret="", discovery_url="https://a/b")


def test_placeholder_secret_key_is_refused():
    """Shipping the sample value would mean guessable session tokens."""
    with pytest.raises(ValueError, match="secret_key"):
        AuthSettings(secret_key="change-me-in-production")
    with pytest.raises(ValueError, match="secret_key"):
        AuthSettings(secret_key="")
