"""File: scripts/generate_auth_secrets.py
Generate local authentication secrets and an RS256 signing key pair.

Run locally, then move the values into your secret manager. Do not commit the
printed values or generated PEM material to source control.
"""

from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def main() -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65_537,
        key_size=3_072,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    print(f"AUTH_PEPPER={secrets.token_urlsafe(48)}")
    print(f"JWT_SECRET={secrets.token_urlsafe(64)}")
    print(f"JWT_PRIVATE_KEY_B64={_b64(private_pem)}")
    print(f"JWT_PUBLIC_KEY_B64={_b64(public_pem)}")
    print(f"JWT_KEY_ID=auth-{secrets.token_hex(6)}")


if __name__ == "__main__":
    main()
