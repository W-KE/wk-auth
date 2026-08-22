"""Fernet encryption for secrets an app stores in its own database —
API keys for upstream services, mostly.

Not a substitute for a real secrets manager, but it keeps the database file
from being a plaintext credential dump if it ends up in a backup.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet


class SecretBox:
    """Encrypt/decrypt bound to one app's secret key.

    A class rather than module functions because the key comes from the
    app's settings; a shared package has no business reaching for a global.
    """

    def __init__(self, secret_key: str):
        # Derive a valid 32-byte urlsafe-base64 Fernet key from the app's
        # SECRET_KEY (which may be any length or format) rather than making
        # the operator provision a second, differently-formatted key.
        digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
