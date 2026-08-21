import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_hasher = PasswordHasher()
_BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if hashed_password.startswith(_BCRYPT_PREFIXES):
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(hashed_password: str) -> bool:
    if hashed_password.startswith(_BCRYPT_PREFIXES):
        return True
    try:
        return _hasher.check_needs_rehash(hashed_password)
    except InvalidHashError:
        return False
