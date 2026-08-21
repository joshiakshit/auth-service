import uuid

import pytest
from jose import jwt


async def _login(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "Test1234"},
    )
    return response.json()["access_token"]


@pytest.mark.asyncio
async def test_access_token_signed_with_rs256_and_full_claims(client, test_user):
    token = await _login(client)

    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert header["kid"]

    claims = jwt.get_unverified_claims(token)
    assert claims["sub"] == str(test_user.id)
    uuid.UUID(claims["sub"])
    assert claims["email"] == test_user.email
    assert claims["email_verified"] is False
    assert "name" in claims
    assert "exp" in claims
    assert "iat" in claims


@pytest.mark.asyncio
async def test_jwks_endpoint_exposes_public_key(client):
    response = await client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    body = response.json()
    assert "keys" in body and len(body["keys"]) >= 1

    key = body["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["kid"]
    assert key["n"]
    assert key["e"]


@pytest.mark.asyncio
async def test_token_verifiable_offline_with_jwks(client, test_user):
    token = await _login(client)
    jwks = (await client.get("/.well-known/jwks.json")).json()

    header = jwt.get_unverified_header(token)
    jwk = next(k for k in jwks["keys"] if k["kid"] == header["kid"])

    claims = jwt.decode(token, jwk, algorithms=["RS256"])
    assert claims["sub"] == str(test_user.id)
