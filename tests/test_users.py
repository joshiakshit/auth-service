import pytest


@pytest.mark.asyncio
async def test_get_me(client, test_user, auth_headers):
    response = await client.get("/api/v1/users/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "id" in data


@pytest.mark.asyncio
async def test_get_me_no_auth(client):
    response = await client.get("/api/v1/users/me")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_change_password_success(client, test_user, auth_headers):
    response = await client.patch(
        "/api/v1/users/me/password",
        json={"current_password": "Test1234", "new_password": "NewPass1"},
        headers=auth_headers,
    )
    assert response.status_code == 200

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "NewPass1"},
    )
    assert login.status_code == 200


@pytest.mark.asyncio
async def test_change_password_wrong_current(client, test_user, auth_headers):
    response = await client.patch(
        "/api/v1/users/me/password",
        json={"current_password": "WrongPass1", "new_password": "NewPass1"},
        headers=auth_headers,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_change_password_weak_new(client, test_user, auth_headers):
    response = await client.patch(
        "/api/v1/users/me/password",
        json={"current_password": "Test1234", "new_password": "weak"},
        headers=auth_headers,
    )
    assert response.status_code == 422
