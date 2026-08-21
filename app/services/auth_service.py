import re
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.user import User
from app.services import token_service
from app.utils.security import hash_password, needs_rehash, verify_password


def validate_password_strength(password: str) -> None:
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Password must be at least 8 characters",
        )
    if not re.search(r"[A-Z]", password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Password must contain at least one uppercase letter",
        )
    if not re.search(r"\d", password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Password must contain at least one digit",
        )


async def register_user(
    db: AsyncSession,
    email: str,
    password: str,
    name: str | None = None,
    username: str | None = None,
) -> User:
    validate_password_strength(password)

    user = User(
        email=email,
        hashed_password=hash_password(password),
        name=name,
        username=username,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise _registration_conflict(exc) from exc
    return user


def _registration_conflict(exc: IntegrityError) -> HTTPException:
    constraint = str(getattr(getattr(exc, "orig", None), "constraint_name", "") or "")
    if "username" in constraint:
        detail = "This username is already taken"
    elif "email" in constraint:
        detail = "An account with this email already exists"
    else:
        detail = "An account with these details already exists"
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def update_user_password(user: User, new_password: str) -> None:
    validate_password_strength(new_password)
    user.hashed_password = hash_password(new_password)


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User:
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is not None and _is_locked(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is temporarily locked due to failed login attempts",
        )

    if user is None or not verify_password(password, user.hashed_password):
        if user is not None:
            await _record_failed_login(db, user)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(password)

    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None

    return user


def _is_locked(user: User) -> bool:
    return user.locked_until is not None and user.locked_until > datetime.now(timezone.utc)


async def _record_failed_login(db: AsyncSession, user: User) -> None:
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCOUNT_LOCKOUT_MINUTES
        )
        user.failed_login_attempts = 0
    # Commit here so the failed attempt survives the 401 that follows;
    # the request's own transaction would otherwise roll it back.
    await db.commit()


async def create_tokens(db: AsyncSession, user_id: uuid.UUID) -> dict:
    access_token = token_service.create_access_token(str(user_id))
    refresh_token, jti = token_service.create_refresh_token_value(str(user_id))
    await token_service.store_refresh_token(db, user_id, jti)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }
