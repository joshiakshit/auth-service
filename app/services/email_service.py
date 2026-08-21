import logging

logger = logging.getLogger(__name__)


async def send_password_reset_email(email: str, reset_token: str) -> None:
    logger.info("Password reset requested for %s", email)


async def send_verification_email(email: str, verification_token: str) -> None:
    logger.info("Email verification requested for %s", email)
