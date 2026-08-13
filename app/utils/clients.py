from app.config import REGISTERED_CLIENTS


def validate_client(client_id: str, redirect_uri: str) -> bool:
    client = REGISTERED_CLIENTS.get(client_id)
    if client is None:
        return False
    return redirect_uri in client.get("redirect_uris", [])


def get_client_name(client_id: str) -> str | None:
    client = REGISTERED_CLIENTS.get(client_id)
    if client is None:
        return None
    return client.get("name")
