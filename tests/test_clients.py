from app.utils.clients import get_client_name, validate_client


def test_validate_known_client():
    assert validate_client("portfolio", "https://portfolio.joshiakshit.live/callback")


def test_validate_unknown_client():
    assert not validate_client("unknown", "https://example.com/callback")


def test_validate_wrong_redirect_uri():
    assert not validate_client("portfolio", "https://evil.com/callback")


def test_get_client_name_known():
    assert get_client_name("portfolio") == "Portfolio"


def test_get_client_name_unknown():
    assert get_client_name("nonexistent") is None
