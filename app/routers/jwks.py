from fastapi import APIRouter

from app.utils import jwt_keys

router = APIRouter(tags=["jwks"])


@router.get("/.well-known/jwks.json")
async def get_jwks():
    return jwt_keys.jwks()
