<!-- File: README.md -->

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
- Redis-backed, risk-tiered authentication and API rate limiting for production
- Declarative FastAPI security policies for authenticated module routes

No MFA or API-client authentication routes, services, schemas, repositories, token types, settings, or runtime dependencies are active in this release. The supplied ORM mappings for future database compatibility remain unchanged.

Outbound OTP delivery is intentionally disabled at the notification gateway. OTP generation, hashing, persistence, verification, rate limiting, and expiry are implemented. A production email/SMS provider must be connected before deployment.

## Final ownership rules

- `app/modules/<feature>/routes.py` owns HTTP transport behavior.
- `app/modules/<feature>/dependencies.py` composes FastAPI service, security,
  request-context, and transaction dependencies for that feature.
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
    api_rate_limits.py          generic authenticated API rate-limit policies
    authorization/              effective role/permission loading
    request_context/            typed headers, contexts, and principals
    route_security.py           composable FastAPI security dependency factory
    security_policy.py          immutable route-security metadata and risk tiers
    identities.py               canonical identity keys
    normalization.py            email and phone normalization/masking
    notifications.py            outbound notification boundary
    openapi.py                  shared authentication error metadata
    otp.py                      persistence-agnostic OTP engine
    policies.py                 account, OTP, and password-history policies
    presentation.py             safe user projection helper
    workflows/rate_limits.py    payload-aware authentication rate-limit facade
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
    # routes.py, dependencies.py, schemas.py, service.py,
    # repositories.py, openapi.py

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

## Declarative route security

Protected module routes declare one local typed access alias, such as
`AdminUserReadAccess` or `CurrentUserWriteAccess`. That alias composes bearer
authentication, persisted-session and account validation, optional header
consistency checks, fresh role/permission enforcement, and a risk-appropriate
API rate limit. Route bodies therefore contain use-case transport logic rather
than repeated security calls.

The generic policies are intentionally risk based:

| Policy | Intended use |
| --- | --- |
| `STANDARD` | Authenticated profile and ordinary reads |
| `SENSITIVE` | Profile/password changes and session revocation |
| `ADMIN_READ` | Administrative list and detail operations |
| `ADMIN_WRITE` | Administrative mutations and assignments |
| `NONE` | Explicit exceptions such as gateway-managed endpoints |

Login, registration, OTP, password-reset, refresh, and refresh-token logout
retain their specialized rate-limit methods because their strongest keys come
from validated payload values, not only route metadata. Ordinary Python route
decorators are not used; FastAPI dependencies preserve dependency overrides,
request validation, signatures, and OpenAPI behavior.

`RATE_LIMIT_BACKEND=disabled` is a development/test facility only. Production
configuration rejects it and requires the Redis backend. There is deliberately
no global authorization-bypass setting.

## Public API groups

The reviewed method, authentication, permission, purpose, consumer, and
keep/remove decisions are recorded in `ENDPOINT_INVENTORY.md`.

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
GET  /api/v1/auth/capabilities
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
GET   /api/v1/auth/users/me/authorization
```

## Authentication and authorization contract

Every login, verification, registration-completion, password-completion, and
refresh flow returns one `TokenPairResponse` containing a minimal
`AuthenticatedUserResponse`. The user object never contains roles or
permissions.

The access token contains only registered JWT claims plus `token_type`, `sid`,
and `amr`. `sub` is the authenticated user UUID; there is no `user_id` claim.
Access and refresh tokens contain no roles, permissions, profile data, device
data, or contract-version claim.

Every protected request validates the access token and then loads the active
session, account, and current effective authorization from PostgreSQL. Clients
fetch their current roles and permissions from:

```text
GET /api/v1/auth/users/me/authorization
Authorization: Bearer <access-token>
```

Frontend permissions are presentation hints, not a security boundary. A user
can alter browser state and request payloads; every protected operation must
still enforce authorization on the server. For the same reason, this service
does not expose an anonymous permission-catalog endpoint.

This deployment is a hard authentication-contract cutover. Rotate the JWT
signing key and remove the prior public key from the decoding-key registry when
the release is deployed; existing access and refresh tokens then become
invalid and every user must authenticate again. Removed
`/api/v1/users/me/roles` and `/api/v1/users/me/permissions` routes return 404.

`GET /api/v1/auth/capabilities` is anonymous and cacheable. It exposes only
client-safe registration, login, verification, password, and platform
capabilities; it is not an authorization catalog.

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
GET    /api/v1/admin/permissions
POST   /api/v1/admin/permissions
GET    /api/v1/admin/permissions/{permission_id}
PATCH  /api/v1/admin/permissions/{permission_id}
DELETE /api/v1/admin/permissions/{permission_id}
GET    /api/v1/admin/roles/{role_id}/permissions
PUT    /api/v1/admin/roles/{role_id}/permissions
```

### User-role assignments

```text
GET    /api/v1/admin/users/{user_id}/roles
POST   /api/v1/admin/users/{user_id}/roles
PATCH  /api/v1/admin/users/{user_id}/roles/{user_role_id}
DELETE /api/v1/admin/users/{user_id}/roles/{user_role_id}
```

## Header contract and trust model

OpenAPI exposes only headers used by each endpoint:

- Rate-limited anonymous operations: `X-Client-ID`, `X-Device-ID`.
- Session-creating operations: `X-Client-ID`, `X-Platform`,
  `X-Device-ID`, `X-Device-Type`.
- Refresh: `X-Client-ID`, `X-Device-ID`.
- Bearer-protected operations declare no custom identity headers.
- `Authorization` is supplied through Swagger's **Authorize** dialog using
  `Bearer <signed-access-token>`; it is not duplicated as a normal parameter.
- `X-Request-ID`, `X-Correlation-ID`, and `User-Agent` are processed by shared
  request infrastructure rather than repeated on every operation.

Security rules:

- `X-User-ID` and `X-Session-ID` are not supported.
- Refresh preserves an omitted device assertion, rejects a
  mismatching assertion with the generic authentication response, and never
  rebinds a session that has no stored device ID.
- Stored session `device_id` and `device_type` values are immutable after
  session creation; clients must create a new session to establish new device
  metadata.
- No metadata header creates an authenticated principal.
- The signed JWT and persisted session are authoritative.
- `X-Forwarded-For` is ignored unless the direct peer is an allowlisted proxy.
- Tokens, passwords, OTPs, cookies, authorization headers, secrets, and hashes are redacted from logs.

## Contract examples

Login, verification completion, password completion, and refresh all return the
same data shape:

```json
{
  "access_token": "<access-token>",
  "refresh_token": "<refresh-token>",
  "token_type": "Bearer",
  "access_expires_at": "2026-07-31T07:30:00Z",
  "refresh_expires_at": "2026-08-30T07:15:00Z",
  "user": {
    "id": "5a9fcb15-f491-4ce3-93cf-f827694845c6",
    "email": "user@example.com",
    "email_verified": true,
    "phone_country_code": "+91",
    "phone_number_masked": "+91******0001",
    "phone_verified": true,
    "status": "active",
    "preferred_locale": "en-IN",
    "timezone": "Asia/Kolkata",
    "display_name": "Example User",
    "profile": null
  }
}
```

Decoded access-token claims:

```json
{
  "sub": "5a9fcb15-f491-4ce3-93cf-f827694845c6",
  "token_type": "access",
  "jti": "40da960e-e701-4976-b93b-c9f516c9d974",
  "sid": "17157083-e4f2-48b4-9571-19e030d0ee7d",
  "iat": 1785482100,
  "nbf": 1785482100,
  "exp": 1785483000,
  "iss": "pharmacy-platform-identity",
  "aud": "pharmacy-platform",
  "amr": ["password"]
}
```

Decoded refresh-token claims use the same registered claims, omit `amr`, and
add only `"fam": "<refresh-family-uuid>"` with
`"token_type": "refresh"`.

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

See `Architecture.md` for the detailed design and `deployment_guide.md` for production deployment guidance.
