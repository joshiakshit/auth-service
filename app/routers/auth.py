from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.user import UserRead
from app.services import auth_service, token_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    user = await auth_service.register_user(db, body.email, body.password)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
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
