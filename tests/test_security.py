import bcrypt
import pytest

from app.utils import security


def test_hash_password_uses_argon2id():
    hashed = security.hash_password("Test1234")
    assert hashed.startswith("$argon2id$")


def test_hash_password_is_salted_per_call():
    assert security.hash_password("Test1234") != security.hash_password("Test1234")


def test_verify_password_roundtrip():
    hashed = security.hash_password("Test1234")
    assert security.verify_password("Test1234", hashed)
    assert not security.verify_password("Wrong1234", hashed)


def test_verify_password_accepts_legacy_bcrypt():
    legacy = bcrypt.hashpw(b"Test1234", bcrypt.gensalt()).decode("utf-8")
    assert security.verify_password("Test1234", legacy)
    assert not security.verify_password("Wrong1234", legacy)


def test_needs_rehash_true_for_bcrypt_false_for_argon2():
    legacy = bcrypt.hashpw(b"Test1234", bcrypt.gensalt()).decode("utf-8")
    assert security.needs_rehash(legacy)
    assert not security.needs_rehash(security.hash_password("Test1234"))


@pytest.mark.asyncio
async def test_login_upgrades_legacy_bcrypt_hash(client, db_session):
    from sqlalchemy import select

    from app.models.user import User

    legacy_hash = bcrypt.hashpw(b"Test1234", bcrypt.gensalt()).decode("utf-8")
    user = User(email="legacy@example.com", hashed_password=legacy_hash)
    db_session.add(user)
    await db_session.commit()

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "legacy@example.com", "password": "Test1234"},
    )
    assert response.status_code == 200

    result = await db_session.execute(select(User).where(User.email == "legacy@example.com"))
    refreshed = result.scalar_one()
    assert refreshed.hashed_password.startswith("$argon2id$")
