import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.refresh_token import RefreshToken


def create_access_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token_value(user_id: str) -> tuple[str, str]:
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "refresh",
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    }
    raw_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return raw_token, jti


def hash_token(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()


def decode_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


async def store_refresh_token(db: AsyncSession, user_id: uuid.UUID, jti: str) -> None:
    token_hash = hash_token(jti)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    db_token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(db_token)
    await db.flush()


async def revoke_refresh_token(db: AsyncSession, jti: str) -> bool:
    token_hash = hash_token(jti)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,  # noqa: E712
        )
    )
    db_token = result.scalar_one_or_none()
    if db_token is None:
        return False
    db_token.revoked = True
    await db.flush()
    return True


async def validate_refresh_token(db: AsyncSession, token: str) -> dict | None:
    payload = decode_token(token)
    if payload is None or payload.get("type") != "refresh":
        return None

    jti = payload.get("jti")
    if jti is None:
        return None

    token_hash = hash_token(jti)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,  # noqa: E712
        )
    )
    db_token = result.scalar_one_or_none()
    if db_token is None:
        return None

    if db_token.expires_at < datetime.now(timezone.utc):
        return None

    return payload


async def revoke_all_user_tokens(db: AsyncSession, user_id: uuid.UUID) -> None:
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False,  # noqa: E712
        )
    )
    tokens = result.scalars().all()
    for token in tokens:
        token.revoked = True
    await db.flush()
