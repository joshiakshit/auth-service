import pytest


def _assert_error_shape(body):
    assert set(body.keys()) >= {"error", "detail"}
    assert isinstance(body["error"], str)
    assert isinstance(body["detail"], str)


@pytest.mark.asyncio
async def test_http_error_uses_standard_schema(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "Whatever1"},
    )
    assert response.status_code == 401
    body = response.json()
    _assert_error_shape(body)
    assert body["error"] == "unauthorized"


@pytest.mark.asyncio
async def test_conflict_error_uses_standard_schema(client, test_user):
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "test@example.com", "password": "Strong1Pass"},
    )
    assert response.status_code == 409
    body = response.json()
    _assert_error_shape(body)
    assert body["error"] == "conflict"


@pytest.mark.asyncio
async def test_validation_error_detail_is_string(client):
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": "Strong1Pass"},
    )
    assert response.status_code == 422
    body = response.json()
    _assert_error_shape(body)
    assert body["error"] == "validation_error"
