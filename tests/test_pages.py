import pytest


@pytest.mark.asyncio
async def test_login_page_no_params(client):
    response = await client.get("/login")
    assert response.status_code == 200
    assert "Sign in" in response.text


@pytest.mark.asyncio
async def test_login_page_with_valid_client(client):
    response = await client.get(
        "/login",
        params={
            "client_id": "portfolio",
            "redirect_uri": "https://portfolio.joshiakshit.live/callback",
        },
    )
    assert response.status_code == 200
    assert "Portfolio" in response.text


@pytest.mark.asyncio
async def test_login_page_invalid_redirect(client):
    response = await client.get(
        "/login",
        params={
            "client_id": "portfolio",
            "redirect_uri": "https://evil.com/callback",
        },
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_login_page_unknown_client(client):
    response = await client.get(
        "/login",
        params={
            "client_id": "unknown",
            "redirect_uri": "https://example.com/callback",
        },
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_login_page_missing_redirect_uri(client):
    response = await client.get("/login", params={"client_id": "portfolio"})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_register_page_no_params(client):
    response = await client.get("/register")
    assert response.status_code == 200
    assert "Create" in response.text


@pytest.mark.asyncio
async def test_register_page_with_valid_client(client):
    response = await client.get(
        "/register",
        params={
            "client_id": "portfolio",
            "redirect_uri": "https://portfolio.joshiakshit.live/callback",
        },
    )
    assert response.status_code == 200
    assert "Portfolio" in response.text


@pytest.mark.asyncio
async def test_forgot_password_page(client):
    response = await client.get("/forgot-password")
    assert response.status_code == 200
    assert "Reset" in response.text
