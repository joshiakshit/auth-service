import logging

logger = logging.getLogger(__name__)


async def send_password_reset_email(email: str, reset_token: str) -> None:
    # TODO: integrate with Azure SendGrid or SMTP for production
    logger.info("Password reset requested for %s", email)
