# Pharmacy Identity Service

Production-oriented FastAPI authentication and authorization service using Python 3.12+, Pydantic v2, SQLAlchemy 2.x async ORM, PostgreSQL, Argon2id, JWT rotation, OTP, scoped RBAC, and Redis-backed rate limiting.

The application is a modular monolith. Every public API family is implemented as an independent vertical slice under `app/modules`. The `app/auth` package contains reusable authentication infrastructure only.

## Current capabilities

- Email and password registration
- Phone and OTP registration
- Email verification
- Email or phone password login
- Phone OTP login
- Short-lived access tokens
- Rotating refresh tokens with replay detection
- Multiple concurrent device sessions
- Current-session logout, logout from other devices, and logout from all devices
- Active-session listing and targeted session revocation
- Password recovery with OTP and a one-time signed reset proof
- Password change and initial password setup
- Current-user profile preferences
- Effective roles and permissions
- Administrative user, role, permission, role-permission, and user-role management
- Scoped and time-bound role assignments
- Purpose-specific OTP challenges with hashing, expiry, cooldown, attempt limits, and replay prevention
- Typed request and device headers in OpenAPI
- Structured logging with credential redaction
- Redis-backed authentication rate limiting for production

No MFA or API-client authentication routes, services, schemas, repositories, token types, settings, or runtime dependencies are active in this release. The supplied ORM mappings for future database compatibility remain unchanged.

Outbound OTP delivery is intentionally disabled at the notification gateway. OTP generation, hashing, persistence, verification, rate limiting, and expiry are implemented. A production email/SMS provider must be connected before deployment.

## Final ownership rules

- `app/modules/<feature>/routes.py` owns HTTP transport behavior.
- `app/modules/<feature>/schemas.py` owns request contracts and feature-specific responses.
- `app/modules/<feature>/service.py` owns use-case orchestration and transaction boundaries.
- `app/modules/<feature>/repositories.py` owns SQLAlchemy persistence operations.
- `app/modules/<feature>/openapi.py` owns tags and response metadata.
- `app/auth` owns shared JWT, password, OTP, request-context, header, session-token, authorization, notification, and rate-limit infrastructure.
- `app/common/auth_contracts.py` owns only identical response contracts reused by several modules.
- Repositories never commit. `SQLAlchemyUnitOfWork` owns commit and rollback.
- ORM models are not public API schemas.
- Business modules may import `app/auth`; `app/auth` must never import a business module.
- Client-provided identity headers are assertions, never authentication credentials.
- Logs use the central logger or `app.utils.debug.debug`. Application code does not use arbitrary `print()` calls.

## Project structure

```text
app/
  api/                          API composition and exception handlers
  auth/                         shared authentication kernel only
    security/
      hashing.py                HMAC and OTP hashing
      passwords.py              Argon2 password policy and verification
      tokens.py                 access, refresh, and reset JWTs
    authorization.py            effective role/permission loading
    context.py                  normalized request metadata
    dependencies.py             JWT/session/role/permission dependencies
    headers.py                  typed OpenAPI headers
    identities.py               canonical identity keys
    normalization.py            email and phone normalization/masking
    notifications.py            outbound notification boundary
    openapi.py                  shared authentication error metadata
    otp.py                      persistence-agnostic OTP engine
    policies.py                 account, OTP, and password-history policies
    presentation.py             safe user projection helper
    principals.py               authenticated user principal
    rate_limits.py              authentication rate-limit facade
    runtime.py                  immutable process-wide security container
    session_tokens.py           session and token-pair issuer
  common/
    auth_contracts.py           truly shared response DTOs
    schemas.py                  strict schema bases and device context
  core/                         configuration, logging, middleware, rate limiting
  db/                           PostgreSQL adapter and Unit of Work
  models/                       externally migrated ORM mappings
  modules/
    registration/
    email_verification/
    login/
    token_management/
    session_management/
    password_management/
    current_user/
    admin_users/
    admin_roles/
    admin_permissions/
    admin_user_roles/

    # Every module contains:
    # routes.py, schemas.py, service.py, repositories.py, openapi.py

  utils/
    debug.py                    development-only redacted debug helper

tests/
  unit/
  contract/
  integration/
```

The following directories intentionally do not exist:

```text
app/auth/services/
app/auth/repositories/
app/auth/schemas/
app/modules/auth/
```

## Public API groups

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
GET  /api/v1/auth/.well-known/jwks.json
POST /api/v1/auth/token/refresh
POST /api/v1/auth/logout
POST /api/v1/auth/logout/others
POST /api/v1/auth/logout/all
```

### Sessions

```text
GET    /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/{session_id}
```

### Password lifecycle

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
GET   /api/v1/users/me/roles
GET   /api/v1/users/me/permissions
```

### Administrative users

```text
GET   /api/v1/admin/users
GET   /api/v1/admin/users/{user_id}
PATCH /api/v1/admin/users/{user_id}/status
POST  /api/v1/admin/users/{user_id}/logout-all
```

### Administrative roles

```text
GET    /api/v1/admin/roles
POST   /api/v1/admin/roles
GET    /api/v1/admin/roles/{role_id}
PATCH  /api/v1/admin/roles/{role_id}
DELETE /api/v1/admin/roles/{role_id}
```

### Permissions and role permissions

```text
GET /api/v1/admin/permissions
GET /api/v1/admin/roles/{role_id}/permissions
PUT /api/v1/admin/roles/{role_id}/permissions
```

### User-role assignments

```text
GET    /api/v1/admin/users/{user_id}/roles
POST   /api/v1/admin/users/{user_id}/roles
PATCH  /api/v1/admin/users/{user_id}/roles/{user_role_id}
DELETE /api/v1/admin/users/{user_id}/roles/{user_role_id}
```

## Header contract and trust model

OpenAPI documents these headers where relevant:

```text
Authorization: Bearer <signed-access-token>
X-Request-ID: <uuid>
X-Correlation-ID: <uuid>
X-Client-ID: <application-id>
X-Client-Version: <version>
X-Platform: web|android|ios|service
X-Device-ID: <stable-device-id>
X-Device-Type: <device-type>
X-Device-Name: <display-name>
X-User-ID: <uuid>
X-Session-ID: <uuid>
Idempotency-Key: <unique-key>
User-Agent: <client-user-agent>
```

Security rules:

- `X-User-ID` must match the JWT `sub` claim when supplied.
- `X-Session-ID` must match the JWT `sid` claim when supplied.
- `X-Device-ID` must match persisted session metadata when both are present.
- No metadata header creates an authenticated principal.
- The signed JWT and persisted session are authoritative.
- `X-Forwarded-For` is ignored unless the direct peer is an allowlisted proxy.
- Tokens, passwords, OTPs, cookies, authorization headers, secrets, and hashes are redacted from logs.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate                # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env                    # Windows: copy .env.example .env
python scripts/generate_auth_secrets.py
```

Copy generated values into `.env`. Never commit `.env`.

```bash
docker compose up -d postgres redis
uvicorn app.main:app --host 0.0.0.0 --port 5555 --reload
```

The external migration service must create and migrate the `identity` schema before readiness succeeds.

## Verification

```bash
python -m compileall -q app tests
pytest -q
ruff check app tests
ruff format --check app tests
mypy app
```

The PostgreSQL integration test is opt-in:

```bash
RUN_POSTGRES_INTEGRATION=true \
POSTGRES_URL='postgresql+asyncpg://identity_app:password@127.0.0.1:5432/pharmacy_platform' \
pytest -m integration -q
```

See `Architecture.md`, `AUTH_REFACTOR_REPORT.md`, and `VALIDATION_REPORT.md` for the design and validation record.
