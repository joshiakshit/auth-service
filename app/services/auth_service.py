import re
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.user import User
from app.services import token_service
from app.utils.security import hash_password, verify_password


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

    if user is None or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    return user


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
