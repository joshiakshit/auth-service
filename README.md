# Auth Service

A standalone authentication service built with FastAPI and PostgreSQL. Provides JWT-based authentication with access/refresh token pairs, an OAuth-style redirect login flow for client applications, and server-rendered login/register pages.

Live at **https://auth.joshiakshit.live/login**

## Features

- User registration and login with password strength validation
- JWT access tokens (15 min) and refresh tokens (7 day, rotated)
- OAuth-style redirect flow — client apps redirect users here to authenticate, then receive tokens via URL fragment callback
- Server-rendered login, register, and forgot-password pages with dark/light theme
- Password reset via email token (single-use)
- Email verification flow with `is_verified` flag
- Rate limiting (per-IP, per-endpoint) and account lockout after repeated failed logins
- Security headers (HSTS, X-Frame-Options, CSP permissions)

## Tech Stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy 2.0 (async), asyncpg
- **Auth**: python-jose (RS256 JWT + JWKS), argon2id password hashing
- **Database**: PostgreSQL 16
- **Templates**: Jinja2
- **Infrastructure**: Docker, Nginx, Let's Encrypt, Azure VM
- **CI/CD**: GitHub Actions, GitHub Container Registry

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/register` | Create account |
| POST | `/api/v1/auth/login` | Get access + refresh tokens |
| POST | `/api/v1/auth/logout` | Revoke refresh token |
| POST | `/api/v1/auth/refresh` | Rotate tokens |
| POST | `/api/v1/auth/password-reset/request` | Request reset email |
| POST | `/api/v1/auth/password-reset/confirm` | Set new password |
| POST | `/api/v1/auth/verify-email/request` | Request verification email |
| POST | `/api/v1/auth/verify-email` | Confirm email address |
| GET | `/api/v1/users/me` | Get current user profile |
| PATCH | `/api/v1/users/me/password` | Change password |
| GET | `/health` | Health check |
| GET | `/.well-known/jwks.json` | Public keys for offline JWT verification |

Full API docs available at `/docs` (Swagger) and `/redoc`.

> **Password reset vs. encrypted data:** the account password reset only
> restores access to the account. If a client system protects data with a
> separate encryption passphrase (for example an encrypted vault), resetting
> the account password does **not** recover that data. These are different
> credentials, and any UI built on this service must say so clearly.

## Redirect Login Flow

Client apps can use this service for authentication by redirecting users:

```
https://auth.joshiakshit.live/login?client_id=portfolio&redirect_uri=https://portfolio.joshiakshit.live/callback
```

After login, the user is redirected back with the token in the URL fragment:

```
https://portfolio.joshiakshit.live/callback#token=eyJhbGci...
```

Register client apps in `app/config.py`:

```python
REGISTERED_CLIENTS = {
    "portfolio": {
        "name": "Portfolio",
        "redirect_uris": ["https://portfolio.joshiakshit.live/callback"],
    },
}
```

## Local Development

### Prerequisites

- Python 3.12+
- PostgreSQL running locally (or via Docker)

### Setup

```bash
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows

pip install -r requirements-dev.txt

# Create .env file
cat > .env <<EOF
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/auth_db
JWT_SECRET_KEY=your-secret-key-here
APP_ENV=development
EOF

# Run migrations
alembic upgrade head

# Start the server
uvicorn app.main:app --reload
```

### Running Tests

```bash
pytest tests/ -v
```

Requires a `auth_db_test` PostgreSQL database.

### Linting

```bash
ruff check app/ tests/
ruff format --check app/ tests/
```

## Deployment

The service deploys automatically on push to `master` via GitHub Actions:

1. CI runs tests and linting
2. Docker image is built and pushed to `ghcr.io/joshiakshit/auth-service`
3. Image is pulled on the VM, migrations run, containers restart

### Production Stack

```
Nginx (SSL termination, port 443)
  -> FastAPI / Uvicorn (port 8000, internal)
  -> PostgreSQL 16 (port 5432, internal)
  + Certbot (auto-renews SSL certificates)
```

All services run via Docker Compose on an Azure VM.

## Project Structure

```
app/
  config.py          # Settings and client registry
  database.py        # Async SQLAlchemy engine and session
  dependencies.py    # Auth dependency (extract user from JWT)
  main.py            # App factory, middleware, router mounting
  models/            # SQLAlchemy models (User, RefreshToken)
  routers/           # API and page route handlers
  schemas/           # Pydantic request/response models
  services/          # Business logic (auth, tokens, email)
  utils/             # Client validation, rate limiting, security
templates/           # Jinja2 HTML templates
nginx/               # Nginx configuration
tests/               # pytest async tests (34 tests)
```
