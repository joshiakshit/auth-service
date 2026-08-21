import pytest
from sqlalchemy import select

from app.models.user import User
from app.services import token_service


@pytest.mark.asyncio
async def test_register_sends_verification_email(client, monkeypatch):
    sent = {}

    async def fake_send(email, token):
        sent["email"] = email
        sent["token"] = token

    monkeypatch.setattr("app.routers.auth.email_service.send_verification_email", fake_send)

    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "verifyme@example.com", "password": "Strong1Pass"},
    )
    assert response.status_code == 201
    assert response.json()["is_verified"] is False
    assert sent["email"] == "verifyme@example.com"


@pytest.mark.asyncio
async def test_verify_email_success(client, test_user, db_session):
    assert test_user.is_verified is False
    token = token_service.create_email_verification_token(str(test_user.id))

    response = await client.post(
        "/api/v1/auth/verify-email",
        json={"token": token},
    )
    assert response.status_code == 200

    result = await db_session.execute(select(User).where(User.id == test_user.id))
    refreshed = result.scalar_one()
    assert refreshed.is_verified is True


@pytest.mark.asyncio
async def test_verify_email_invalid_token(client):
    response = await client.post(
        "/api/v1/auth/verify-email",
        json={"token": "not.a.valid.token"},
    )
    assert response.status_code == 400
