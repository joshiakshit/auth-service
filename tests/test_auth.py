import pytest


@pytest.mark.asyncio
async def test_register_success(client):
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "new@example.com", "password": "Strong1Pass"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "new@example.com"
    assert "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client, test_user):
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "test@example.com", "password": "Strong1Pass"},
    )
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_register_weak_password_no_uppercase(client):
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "weak@example.com", "password": "nouppercase1"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_weak_password_no_digit(client):
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "weak@example.com", "password": "NoDigitHere"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_weak_password_too_short(client):
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "weak@example.com", "password": "Ab1"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client, test_user):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "Test1234"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 900


@pytest.mark.asyncio
async def test_login_wrong_password(client, test_user):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "WrongPass1"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "Whatever1"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_logout_success(client, test_user):
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "Test1234"},
    )
    tokens = login.json()

    response = await client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_logout_without_auth(client):
    response = await client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": "fake"},
    )
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_refresh_success(client, test_user):
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "Test1234"},
    )
    tokens = login.json()

    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert response.status_code == 200
    new_tokens = response.json()
    assert "access_token" in new_tokens
    assert new_tokens["refresh_token"] != tokens["refresh_token"]
    assert new_tokens["expires_in"] == 900


@pytest.mark.asyncio
async def test_refresh_reuse_old_token(client, test_user):
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "Test1234"},
    )
    old_refresh = login.json()["refresh_token"]

    await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh},
    )

    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_invalid_token(client):
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "not.a.real.token"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_request_always_200(client):
    response = await client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": "nobody@example.com"},
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_password_reset_confirm_invalid_token(client):
    response = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": "bad.token.here", "new_password": "NewPass1"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_password_reset_confirm_success(client, test_user):
    from app.services import token_service

    token = token_service.create_password_reset_token(str(test_user.id))
    response = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "NewPass1"},
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_password_reset_confirm_token_single_use(client, test_user):
    from app.services import token_service

    token = token_service.create_password_reset_token(str(test_user.id))

    first = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "NewPass1"},
    )
    assert first.status_code == 200

    second = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "OtherPass2"},
    )
    assert second.status_code == 400
