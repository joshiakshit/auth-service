from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    MessageResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.user import UserRead
from app.services import auth_service, email_service, token_service
from app.utils.rate_limit import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
async def register(request: Request, body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    user = await auth_service.register_user(db, body.email, body.password)
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = await auth_service.authenticate_user(db, body.email, body.password)
    tokens = await auth_service.create_tokens(db, user.id)
    return tokens


@router.post("/logout", response_model=MessageResponse)
async def logout(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    payload = token_service.decode_token(body.refresh_token)
    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token",
        )

    revoked = await token_service.revoke_refresh_token(db, payload["jti"])
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token already revoked or not found",
        )

    return {"message": "Successfully logged out"}


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    payload = await token_service.validate_refresh_token(db, body.refresh_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    await token_service.revoke_refresh_token(db, payload["jti"])

    user_id = UUID(payload["sub"])
    tokens = await auth_service.create_tokens(db, user_id)
    return tokens


@router.post("/password-reset/request", response_model=MessageResponse)
@limiter.limit("3/minute")
async def request_password_reset(
    request: Request,
    body: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if user is not None:
        reset_token = token_service.create_password_reset_token(str(user.id))
        await email_service.send_password_reset_email(body.email, reset_token)

    return {"message": "If an account with that email exists, a reset link has been sent"}


@router.post("/password-reset/confirm", response_model=MessageResponse)
async def confirm_password_reset(body: PasswordResetConfirm, db: AsyncSession = Depends(get_db)):
    payload = token_service.decode_token(body.token)
    if payload is None or payload.get("type") != "password_reset":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    user_id = UUID(payload["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token",
        )

    auth_service.update_user_password(user, body.new_password)
    await token_service.revoke_all_user_tokens(db, user.id)
    await db.flush()

    return {"message": "Password has been reset successfully"}
