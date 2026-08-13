from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.utils.clients import get_client_name, validate_client

router = APIRouter(tags=["pages"])
templates = Jinja2Templates(directory="templates")


def _resolve_client_context(
    client_id: str | None,
    redirect_uri: str | None,
) -> dict:
    if client_id and redirect_uri:
        if not validate_client(client_id, redirect_uri):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unknown application or invalid redirect URI",
            )
        return {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "client_name": get_client_name(client_id),
        }

    if client_id or redirect_uri:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Both client_id and redirect_uri are required",
        )

    return {"client_id": "", "redirect_uri": "", "client_name": ""}


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    client_id: str | None = None,
    redirect_uri: str | None = None,
):
    ctx = _resolve_client_context(client_id, redirect_uri)
    return templates.TemplateResponse(request, "login.html", ctx)


@router.get("/register", response_class=HTMLResponse)
async def register_page(
    request: Request,
    client_id: str | None = None,
    redirect_uri: str | None = None,
):
    ctx = _resolve_client_context(client_id, redirect_uri)
    return templates.TemplateResponse(request, "register.html", ctx)


@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse(request, "forgot_password.html", {})
