<!-- File: README.md -->

<h1 align="center">🔐 Pharmacy Identity Service</h1>

<p align="center">
  Production-focused authentication and authorization service built with FastAPI, PostgreSQL, Redis, JWT, Argon2id, and database-backed RBAC.
</p>

<p align="center">
  <img height="22" alt="Python 3.12+" src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white">
  <img height="22" alt="FastAPI" src="https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white">
  <img height="22" alt="PostgreSQL Async" src="https://img.shields.io/badge/PostgreSQL-Async-4169E1?logo=postgresql&logoColor=white">
  <img height="22" alt="Redis Rate Limiting" src="https://img.shields.io/badge/Redis-Rate%20Limiting-DC382D?logo=redis&logoColor=white">
  <img height="22" alt="Docker API Service" src="https://img.shields.io/badge/Docker-API%20Service-2496ED?logo=docker&logoColor=white">
  <img height="22" alt="JWT Rotating Tokens" src="https://img.shields.io/badge/JWT-Rotating%20Tokens-000000?logo=jsonwebtokens&logoColor=white">
</p>

---

## Overview

Pharmacy Identity Service provides authentication, session management, OTP verification, password recovery, user profile management, and role-based authorization for the pharmacy platform.

The service follows a modular FastAPI structure:

- Business features are located under `app/modules`.
- Shared authentication infrastructure is located under `app/auth`.
- PostgreSQL is the source of truth for users, sessions, roles, and permissions.
- Redis is used for production rate limiting.
- Access tokens contain authentication and session claims only.
- Roles and permissions are resolved from PostgreSQL.

Detailed architecture decisions are documented in [`Architecture.md`](Architecture.md).

## Documentation map

- [API reference](docs/API.md)
- [Deployment runbook](docs/DEPLOYMENT.md)
- [Architecture](Architecture.md)
- [Environment template](.env.example)

## Features

- Email and password registration
- Phone registration using OTP
- Email verification
- Password login using email or phone
- Phone OTP login
- Short-lived access tokens
- Rotating refresh tokens
- Refresh-token replay detection
- Multiple device sessions
- Session listing and revocation
- Current-session logout
- Logout from other devices
- Logout from all devices
- Forgot-password and reset-password flows
- Initial password setup
- Password change
- Current-user profile management
- Safe public-avatar attachment and CDN URL projection
- Database-backed roles and permissions
- Scoped and time-bound role assignments
- Administrative user and RBAC management
- Redis-backed authentication rate limiting
- Structured logging with credential redaction
- Swagger UI and OpenAPI documentation

## Technology stack

| Component | Technology |
| --- | --- |
| Language | Python 3.12+ |
| API framework | FastAPI |
| Validation | Pydantic v2 |
| ORM | SQLAlchemy 2.x Async |
| Database | PostgreSQL |
| Rate limiting | Redis |
| Password hashing | Argon2id |
| Tokens | JWT |
| Testing | Pytest |
| Linting and formatting | Ruff |
| Type checking | MyPy |
| Containerization | Docker |

## Project structure

```text
app/
├── api/                    API router composition and exception handlers
├── auth/                   Shared authentication infrastructure
│   ├── authorization/      Effective role and permission resolution
│   ├── request_context/    Authentication and request context
│   ├── security/           Password, hashing, and token utilities
│   └── workflows/          Shared authentication workflows
├── common/                 Shared schemas and response contracts
├── core/                   Configuration, logging, and middleware
├── db/                     Database adapter and Unit of Work
├── models/                 SQLAlchemy ORM models
├── modules/                Business feature modules
│   ├── registration/
│   ├── email_verification/
│   ├── login/
│   ├── token_management/
│   ├── session_management/
│   ├── password_management/
│   ├── current_user/
│   ├── admin_users/
│   ├── admin_roles/
│   ├── admin_permissions/
│   └── admin_user_roles/
└── utils/                  Shared utilities

tests/
├── unit/
├── contract/
└── integration/
```

## Prerequisites

Install the following before starting:

* Python 3.12 or newer
* PostgreSQL
* Redis
* Git
* Docker and Docker Compose, optional

PostgreSQL and Redis are external dependencies.

The included Docker configuration starts only the Python API service. It does not start PostgreSQL or Redis.

## Local development setup

### 1. Clone the repository

```bash
git clone <repository-url>
cd auth_service
```

### 2. Create a virtual environment

#### Linux or macOS

```bash
python -m venv .venv
source .venv/bin/activate
```

#### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

#### Windows Command Prompt

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
```

### 4. Create the environment file

#### Linux or macOS

```bash
cp .env.example .env
```

#### Windows

```cmd
copy .env.example .env
```

Generate authentication secrets:

```bash
python scripts/generate_auth_secrets.py
```

Copy the generated values into `.env`.

Never commit:

* `.env`
* JWT signing keys
* Database credentials
* Redis credentials
* OTP values
* Access tokens
* Refresh tokens

### 5. Configure PostgreSQL and Redis

Set externally reachable service URLs in `.env`:

```env
POSTGRES_URL=postgresql+asyncpg://identity_app:secure_password@127.0.0.1:5432/pharmacy_platform

RATE_LIMIT_BACKEND=redis
REDIS_URL=redis://127.0.0.1:6379/0
```

When the API runs inside Docker, `127.0.0.1` refers to the API container itself.

Use hostnames or addresses reachable from the container:

```env
POSTGRES_URL=postgresql+asyncpg://identity_app:secure_password@host.docker.internal:5432/pharmacy_platform

RATE_LIMIT_BACKEND=redis
REDIS_URL=redis://host.docker.internal:6379/0
```

For Linux Docker environments, configure the appropriate Docker network hostname or host gateway.

### 6. Prepare the database

The required PostgreSQL tables must exist before application readiness succeeds. Auth
requires its 14 `identity` tables plus `platform.file_objects`, all migrated by
`healthcare_db`.

Run the database migrations using the migration process configured for your environment.

Seed identity master data when required:

```bash
python scripts/seed_identity_master_data.py
```

### 7. Start the API locally

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5555 --reload
```

The API will be available at:

```text
http://localhost:5555
```

## Run with Docker

The Docker configuration runs only the FastAPI service.

PostgreSQL and Redis must already be available through the URLs configured in `.env`.

### Build and start

```bash
docker compose up --build
```

### Run in the background

```bash
docker compose up -d --build
```

### View container status

```bash
docker compose ps
```

### View API logs

```bash
docker compose logs -f api
```

### Restart the API

```bash
docker compose restart api
```

### Stop the API

```bash
docker compose down
```

The application will be available at:

```text
http://localhost:5555
```

## API documentation

FastAPI provides interactive API documentation.

| Documentation  | URL                                  |
| -------------- | ------------------------------------ |
| Swagger UI     | `http://localhost:5555/docs`         |
| ReDoc          | `http://localhost:5555/redoc`        |
| OpenAPI schema | `http://localhost:5555/openapi.json` |

For protected APIs, use Swagger's **Authorize** button and provide:

```text
Bearer <access-token>
```

## Core API groups

### Registration

```text
POST /api/v1/auth/register/email
POST /api/v1/auth/register/phone/request-otp
POST /api/v1/auth/register/phone/verify-otp
```

### Email verification

```text
POST /api/v1/auth/email-verification/request
POST /api/v1/auth/email-verification/verify
```

### Login

```text
POST /api/v1/auth/login/password
POST /api/v1/auth/login/phone/request-otp
POST /api/v1/auth/login/phone/verify-otp
```

### Token and logout lifecycle

```text
POST /api/v1/auth/token/refresh
POST /api/v1/auth/logout
POST /api/v1/auth/logout/others
POST /api/v1/auth/logout/all
```

### Sessions

```text
GET    /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/{sessionId}
```

### Password management

```text
POST /api/v1/auth/password/forgot
POST /api/v1/auth/password/reset/verify-otp
POST /api/v1/auth/password/reset
PUT  /api/v1/auth/password
POST /api/v1/auth/password
```

### Current user

```text
GET   /api/v1/users/me
PATCH /api/v1/users/me
GET   /api/v1/auth/users/me/authorization
```

### Public capabilities

```text
GET /api/v1/auth/capabilities
```

This endpoint does not require authentication.

It exposes client-safe authentication configuration and does not expose roles, permissions, or internal security settings.

### Administrative APIs

Administrative APIs are available for:

* Users
* Roles
* Permissions
* Role-permission assignments
* User-role assignments
* Administrative session revocation

Administrative APIs require a valid access token and the appropriate database-backed permission.

See [`ENDPOINT_INVENTORY.md`](ENDPOINT_INVENTORY.md) for the complete route inventory.

## Authentication contract

The service uses one access-token contract and one refresh-token contract.

### Access token

The access token contains authentication and session claims only:

```json
{
  "sub": "authenticated-user-uuid",
  "token_type": "access",
  "jti": "access-token-uuid",
  "sid": "session-uuid",
  "iat": 1785482100,
  "nbf": 1785482100,
  "exp": 1785483000,
  "iss": "pharmacy-platform-identity",
  "aud": "pharmacy-platform",
  "amr": [
    "password"
  ]
}
```

The access token does not contain:

* A separate `user_id` claim
* Roles
* Permissions
* Email address
* Phone number
* Profile information
* Device information

The standard JWT `sub` claim contains the authenticated user ID.

### Login and refresh response

Login, verification completion, password completion, and token refresh return the same token-pair structure:

```json
{
  "accessToken": "<access-token>",
  "refreshToken": "<refresh-token>",
  "tokenType": "Bearer",
  "accessExpiresAt": "2026-07-31T07:30:00Z",
  "refreshExpiresAt": "2026-08-30T07:15:00Z",
  "user": {
    "id": "5a9fcb15-f491-4ce3-93cf-f827694845c6",
    "email": "user@example.com",
    "emailVerified": true,
    "phoneCountryCode": "+91",
    "phoneNumberMasked": "+91******0001",
    "phoneVerified": true,
    "status": "active",
    "preferredLocale": "en-IN",
    "timezone": "Asia/Kolkata",
    "displayName": "Example User",
    "profile": {
      "firstName": "Example",
      "lastName": "User",
      "preferredName": "Example User",
      "avatar": {
        "id": "22222222-2222-2222-2222-222222222222",
        "url": "https://cdn.example.com/avatars/22222222.webp"
      }
    }
  }
}
```

The login response does not contain roles or permissions. Public avatar URLs are
resolved from `platform.file_objects` in the profile query; auth never returns a
bucket, storage key, encryption reference, private file, or presigned URL.

### Authorization

Current roles and permissions are loaded from PostgreSQL.

Clients can fetch their effective authorization using:

```http
GET /api/v1/auth/users/me/authorization
Authorization: Bearer <access-token>
```

Frontend authorization data is intended for interface behavior only.

Every protected backend operation must independently validate the user's current database-backed permissions.

## Request headers

The service accepts only headers with a defined purpose.

### Request tracing

```text
X-Request-ID
X-Correlation-ID
```

These headers are optional. The application generates identifiers when they are omitted.

### Anonymous rate-limited operations

```text
X-Client-ID
X-Device-ID
```

### Session-creating operations

```text
X-Client-ID
X-Platform
X-Device-ID
X-Device-Type
```

### Protected operations

```text
Authorization: Bearer <access-token>
```

`X-User-ID` and `X-Session-ID` are not supported.

The signed JWT and persisted session are the authoritative identity sources.

## OTP delivery status

OTP generation, hashing, storage, validation, expiry, cooldown, attempt limiting, and replay prevention are implemented.

Outbound email and SMS delivery is currently disabled at the notification gateway.

A production email or SMS provider must be connected before OTP-dependent flows are enabled in production.

## Testing

Run all tests:

```bash
pytest -q
```

Run unit tests:

```bash
pytest tests/unit -q
```

Run contract tests:

```bash
pytest tests/contract -q
```

Run integration tests:

```bash
pytest tests/integration -q
```

### PostgreSQL integration tests

PostgreSQL integration tests are opt-in.

The migrated test database must contain the required `identity` tables and
`platform.file_objects`.

#### Linux or macOS

```bash
RUN_POSTGRES_INTEGRATION=true \
POSTGRES_URL='postgresql+asyncpg://identity_app:password@127.0.0.1:5432/pharmacy_platform' \
pytest -m integration -q
```

#### Windows PowerShell

```powershell
$env:RUN_POSTGRES_INTEGRATION="true"
$env:POSTGRES_URL="postgresql+asyncpg://identity_app:password@127.0.0.1:5432/pharmacy_platform"
pytest -m integration -q
```

## Code quality

Compile the application and tests:

```bash
python -m compileall -q app tests
```

Run Ruff linting:

```bash
ruff check app tests
```

Check formatting:

```bash
ruff format --check app tests
```

Run MyPy:

```bash
mypy app
```

Run the primary verification suite:

```bash
python -m compileall -q app tests
pytest -q
ruff check app tests
ruff format --check app tests
mypy app
```

## Production checklist

Before production deployment:

* Configure production PostgreSQL.
* Configure production Redis.
* Connect production email and SMS providers.
* Configure secure JWT signing keys.
* Remove development placeholder secrets.
* Enable Redis-backed rate limiting.
* Run PostgreSQL integration tests.
* Run dependency vulnerability scanning.
* Run secret scanning.
* Confirm logs redact credentials and tokens.
* Exclude `.env`, private keys, caches, and test artifacts from release packages.
* Verify refresh-token rotation and replay detection.
* Verify session revocation behavior.
* Verify current database-backed authorization.

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for deployment instructions.

## Documentation

| Document                                         | Purpose                             |
| ------------------------------------------------ | ----------------------------------- |
| [`Architecture.md`](Architecture.md)             | Architecture and design decisions   |
| [`ENDPOINT_INVENTORY.md`](ENDPOINT_INVENTORY.md) | Complete API route inventory        |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)     | Production deployment guide         |
| [`.env.example`](.env.example)                   | Environment configuration reference |

## License

Add the applicable project license here.

---

<p align="center">
  Built with FastAPI, PostgreSQL, Redis, SQLAlchemy, and Python.
</p>
