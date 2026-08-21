import base64
import hashlib
import logging
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import settings

logger = logging.getLogger(__name__)

ALGORITHM = "RS256"


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _generate_keypair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _load_key_material() -> tuple[bytes, bytes]:
    if settings.JWT_PRIVATE_KEY and settings.JWT_PUBLIC_KEY:
        return settings.JWT_PRIVATE_KEY.encode("utf-8"), settings.JWT_PUBLIC_KEY.encode("utf-8")

    if settings.JWT_PRIVATE_KEY_PATH and settings.JWT_PUBLIC_KEY_PATH:
        private_path = Path(settings.JWT_PRIVATE_KEY_PATH)
        public_path = Path(settings.JWT_PUBLIC_KEY_PATH)
        if private_path.exists() and public_path.exists():
            return private_path.read_bytes(), public_path.read_bytes()

    logger.warning(
        "No JWT signing keys configured; generated an ephemeral RSA keypair. "
        "Tokens will not survive a restart. Configure JWT_PRIVATE_KEY_PATH for production."
    )
    return _generate_keypair()


_private_pem, _public_pem = _load_key_material()
_public_key = serialization.load_pem_public_key(_public_pem)


def _compute_kid(public_pem: bytes) -> str:
    return hashlib.sha256(public_pem).hexdigest()[:16]


PRIVATE_KEY = _private_pem.decode("utf-8")
PUBLIC_KEY = _public_pem.decode("utf-8")
KID = _compute_kid(_public_pem)


def jwks() -> dict:
    numbers = _public_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": ALGORITHM,
                "kid": KID,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }
