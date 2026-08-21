import pytest
from sqlalchemy import select

from app.config import settings
from app.models.user import User


async def _fail_login(client, times):
    for _ in range(times):
        await client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "WrongPass1"},
        )


@pytest.mark.asyncio
async def test_account_locks_after_max_failed_attempts(client, test_user):
    await _fail_login(client, settings.MAX_FAILED_LOGIN_ATTEMPTS)

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "Test1234"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_successful_login_resets_failed_attempts(client, test_user, db_session):
    await _fail_login(client, settings.MAX_FAILED_LOGIN_ATTEMPTS - 1)

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "Test1234"},
    )
    assert response.status_code == 200

    result = await db_session.execute(select(User).where(User.email == "test@example.com"))
    user = result.scalar_one()
    assert user.failed_login_attempts == 0
    assert user.locked_until is None
