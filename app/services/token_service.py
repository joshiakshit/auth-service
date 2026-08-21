import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.refresh_token import RefreshToken
from app.models.revoked_access_token import RevokedAccessToken
from app.models.used_reset_token import UsedResetToken


def create_access_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "access",
        "jti": str(uuid.uuid4()),
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
        update(RefreshToken)
        .where(RefreshToken.token_hash == token_hash, RefreshToken.revoked == False)
        .values(revoked=True)
    )
    await db.flush()
    return result.rowcount > 0


async def consume_refresh_token(db: AsyncSession, token: str) -> dict | None:
    """Atomically validate and revoke a refresh token in one round trip.

    Using a single conditional UPDATE (rather than a separate read-then-write)
    means Postgres's row lock decides the race: two concurrent calls for the
    same token can never both succeed.
    """
    payload = decode_token(token)
    if payload is None or payload.get("type") != "refresh":
        return None

    jti = payload.get("jti")
    if jti is None:
        return None

    token_hash = hash_token(jti)
    result = await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
        .values(revoked=True)
    )
    await db.flush()

    if result.rowcount != 1:
        return None

    return payload


def create_password_reset_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "password_reset",
        "iat": now,
        "exp": now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_email_verification_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "email_verification",
        "iat": now,
        "exp": now + timedelta(minutes=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


async def consume_reset_token(db: AsyncSession, token: str) -> bool:
    """Claim a password reset token for one-time use.

    The claim is a single INSERT guarded by a UNIQUE constraint, so two
    concurrent confirmations of the same token can never both succeed:
    the loser's row is skipped and this returns False.
    """
    stmt = (
        pg_insert(UsedResetToken)
        .values(token_hash=hash_token(token))
        .on_conflict_do_nothing(index_elements=["token_hash"])
    )
    result = await db.execute(stmt)
    await db.flush()
    return result.rowcount == 1


async def revoke_access_token(db: AsyncSession, jti: str, expires_at: datetime) -> None:
    stmt = (
        pg_insert(RevokedAccessToken)
        .values(jti=jti, expires_at=expires_at)
        .on_conflict_do_nothing(index_elements=["jti"])
    )
    await db.execute(stmt)
    await db.flush()


async def is_access_token_revoked(db: AsyncSession, jti: str) -> bool:
    result = await db.execute(
        select(RevokedAccessToken.id).where(RevokedAccessToken.jti == jti)
    )
    return result.first() is not None


async def revoke_all_user_tokens(db: AsyncSession, user_id: uuid.UUID) -> None:
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False,
        )
    )
    tokens = result.scalars().all()
    for token in tokens:
        token.revoked = True
    await db.flush()
