import asyncio

import pytest

from app.models.user import User
from app.services import token_service
from app.utils.security import hash_password

CONCURRENT_ATTEMPTS = 15


@pytest.mark.asyncio
async def test_refresh_token_concurrent_double_spend_rejected(session_factory):
    async with session_factory() as setup:
        user = User(email="racer@example.com", hashed_password=hash_password("x"))
        setup.add(user)
        await setup.commit()
        await setup.refresh(user)

        refresh_token, jti = token_service.create_refresh_token_value(str(user.id))
        await token_service.store_refresh_token(setup, user.id, jti)
        await setup.commit()

    # Many independent sessions race to consume the same refresh token at
    # the same instant. Exactly one may succeed, no matter how the DB
    # driver interleaves their I/O.
    barrier = asyncio.Barrier(CONCURRENT_ATTEMPTS)

    async def consume():
        async with session_factory() as session:
            await barrier.wait()
            payload = await token_service.consume_refresh_token(session, refresh_token)
            await session.commit()
            return payload is not None

    results = await asyncio.gather(*(consume() for _ in range(CONCURRENT_ATTEMPTS)))

    assert results.count(True) == 1
