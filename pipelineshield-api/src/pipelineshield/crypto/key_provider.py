"""KeyProvider — abstract interface for application-level envelope encryption.

Design principles:
- The key source is always external and injected at runtime.
- No encryption key is ever stored in source code, config files, or committed
  environment files.
- Missing key configuration causes a hard startup error (fail closed) so the
  service never persists plaintext Confidential content.
- The KeyProvider interface is separated from its implementation so that the
  concrete key source (Secrets Manager, environment variable for testing, etc.)
  can be swapped without changing callers.

Envelope encryption scheme:
  1. Generate a random 256-bit data encryption key (DEK).
  2. Encrypt the plaintext with AES-256-GCM using the DEK.
  3. Wrap the DEK with the key encryption key (KEK) held by the KeyProvider.
  4. Store [wrapped_DEK || iv || ciphertext || tag] as a single Base-64 encoded
     blob in the masked_content column.
  5. key_id identifies the KEK version so the decryption path can retrieve the
     correct KEK without storing it in the database.

This prototype implements a passphrase-derived KEK via HKDF (suitable for
testing/development).  Production deployments inject a Secrets Manager-backed
KeyProvider via dependency injection.
"""
from __future__ import annotations

import base64
import os
from abc import ABC, abstractmethod


class EncryptionError(RuntimeError):
    """Raised when encryption or decryption fails."""


class KeyUnavailableError(EncryptionError):
    """Raised at startup if the encryption key cannot be loaded.

    The service must fail closed — refusing to boot — rather than falling
    back to plaintext storage.
    """


class KeyProvider(ABC):
    """Abstract key provider interface.

    Implementations wrap the key management backend (Secrets Manager, KMS,
    environment variable, etc.) so that callers are insulated from the key
    source.
    """

    @property
    @abstractmethod
    def key_id(self) -> str:
        """Stable identifier for the current active key version.

        Stored alongside ciphertext so the decryption path can fetch the
        correct KEK.  MUST NOT return the key value itself.
        """

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Encrypt *plaintext* and return an opaque ciphertext blob.

        The returned value is safe to store in the masked_content column.
        Raises EncryptionError on failure.
        """

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt *ciphertext* (produced by ``encrypt``) and return plaintext.

        Raises EncryptionError on failure (e.g. invalid ciphertext, key
        unavailable, authentication failure).
        """


class EnvKeyProvider(KeyProvider):
    """KeyProvider backed by a runtime environment variable.

    Suitable for local development and CI.  The KEK is derived from the
    value of the ``PIPELINE_SHIELD_DEF_KEY`` environment variable via HKDF.

    Startup behaviour: if the environment variable is absent, raises
    KeyUnavailableError immediately — the service should not start.

    NEVER use this implementation in production — use a Secrets Manager or
    KMS-backed provider instead.
    """

    _ENV_VAR = "PIPELINE_SHIELD_DEF_KEY"

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        raw = os.environ.get(self._ENV_VAR)
        if not raw:
            raise KeyUnavailableError(
                f"Encryption key configuration is missing.  "
                f"Set the {self._ENV_VAR!r} environment variable before "
                f"starting the service.  The service refuses to start "
                f"without a valid encryption key."
            )

        # Derive a 256-bit KEK from the passphrase.
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"pipelineshield-def-kek-v1",
            backend=default_backend(),
        )
        self._kek: bytes = kdf.derive(raw.encode())
        # key_id is a stable hash of the raw passphrase — not the key itself.
        import hashlib
        self._key_id: str = "env-v1-" + hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def key_id(self) -> str:
        return self._key_id

    def encrypt(self, plaintext: str) -> str:
        """Encrypt *plaintext* with AES-256-GCM using envelope encryption.

        Format of the returned blob (base64-encoded):
            [4 bytes: DEK length][wrapped DEK][12 bytes: IV][ciphertext + 16-byte tag]
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # 1. Generate a random 256-bit DEK.
        dek = os.urandom(32)
        # 2. Wrap the DEK with the KEK using AES-256-GCM.
        kek_gcm = AESGCM(self._kek)
        kek_iv = os.urandom(12)
        wrapped_dek: bytes = kek_iv + kek_gcm.encrypt(kek_iv, dek, None)
        # 3. Encrypt the plaintext with the DEK.
        dek_gcm = AESGCM(dek)
        data_iv = os.urandom(12)
        ciphertext: bytes = data_iv + dek_gcm.encrypt(data_iv, plaintext.encode(), None)
        # 4. Assemble: [4-byte wrapped_dek length][wrapped_dek][ciphertext]
        dek_len = len(wrapped_dek).to_bytes(4, "big")
        blob: bytes = dek_len + wrapped_dek + ciphertext
        return base64.b64encode(blob).decode()

    def decrypt(self, ciphertext_blob: str) -> str:
        """Decrypt a blob produced by :meth:`encrypt`."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            raw = base64.b64decode(ciphertext_blob)
        except Exception as exc:
            raise EncryptionError("Ciphertext is not valid base-64.") from exc

        try:
            dek_len = int.from_bytes(raw[:4], "big")
            wrapped_dek = raw[4 : 4 + dek_len]
            ciphertext = raw[4 + dek_len :]

            # Unwrap the DEK.
            kek_gcm = AESGCM(self._kek)
            kek_iv = wrapped_dek[:12]
            dek = kek_gcm.decrypt(kek_iv, wrapped_dek[12:], None)

            # Decrypt the ciphertext.
            dek_gcm = AESGCM(dek)
            data_iv = ciphertext[:12]
            plaintext = dek_gcm.decrypt(data_iv, ciphertext[12:], None)
            return plaintext.decode()
        except EncryptionError:
            raise
        except Exception as exc:
            raise EncryptionError(
                "Decryption failed — key mismatch or corrupt ciphertext."
            ) from exc
