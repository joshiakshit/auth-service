import asyncio

import pytest
from fastapi import HTTPException

from app.services import auth_service


@pytest.mark.asyncio
async def test_register_concurrent_duplicate_email_one_conflict(session_factory):
    barrier = asyncio.Barrier(2)

    async def attempt():
        async with session_factory() as session:
            await barrier.wait()
            try:
                await auth_service.register_user(session, "dupe@example.com", "Strong1Pass")
                await session.commit()
                return "ok"
            except HTTPException as exc:
                return exc.status_code

    results = await asyncio.gather(attempt(), attempt())

    assert sorted(str(r) for r in results) == ["409", "ok"]


@pytest.mark.asyncio
async def test_register_concurrent_duplicate_username_one_conflict(session_factory):
    barrier = asyncio.Barrier(2)

    async def attempt(email):
        async with session_factory() as session:
            await barrier.wait()
            try:
                await auth_service.register_user(session, email, "Strong1Pass", username="taken")
                await session.commit()
                return "ok"
            except HTTPException as exc:
                return exc.status_code

    results = await asyncio.gather(attempt("a@example.com"), attempt("b@example.com"))

    assert sorted(str(r) for r in results) == ["409", "ok"]
