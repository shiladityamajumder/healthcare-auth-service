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
GET   /api/v1/auth/users/me/authorization
GET   /api/v1/users/me/roles        (deprecated compatibility projection)
GET   /api/v1/users/me/permissions  (deprecated compatibility projection)
```

## Authorization-contract migration

The repository-wide consumer inventory, manual-review gates, version-removal
criteria, cache contract, and rollback procedure are recorded in
`AUTHORIZATION_CONTRACT_IMPACT_AUDIT.md`.

Login and refresh support two explicit response contracts:

- `AUTH_LOGIN_REFRESH_RESPONSE_VERSION=1` is the default and preserves the
  existing `user.roles` and `user.permissions` properties.
- `AUTH_LOGIN_REFRESH_RESPONSE_VERSION=2` returns the minimal authenticated
  user profile. Clients then obtain current authorization from
  `GET /api/v1/auth/users/me/authorization`.

Access-token issuance is controlled independently:

- `ACCESS_TOKEN_VERSION=1` is the default and retains the existing role and
  permission claims. Already-issued legacy tokens without `ver` are treated as
  version 1.
- `ACCESS_TOKEN_VERSION=2` adds `ver: 2`, always omits permissions, and includes
  coarse roles only when `ACCESS_TOKEN_V2_INCLUDE_ROLES=true`. The default for
  that setting is false.

Version 2 principals always require a current active persisted session and
load effective roles and permissions from PostgreSQL before route authorization,
even if the general authorization-refresh setting is disabled. The same
effective-authorization query applies global scope, assignment activity,
validity windows, and role/permission soft-delete rules.

Frontend permissions are presentation hints, not a security boundary. A user
can alter browser state and request payloads; every protected operation must
still enforce authorization on the server. For the same reason, this service
does not expose an anonymous permission-catalog endpoint.

### Downstream rollout

1. Keep both version settings at `1` while inventorying JWT and login-response
   consumers.
2. Migrate UI clients to the protected current-authorization endpoint and
   invalidate their cached authorization after login, refresh, and account or
   role changes.
3. Migrate APIs that currently inspect global `permissions` claims. Prefer
   audience-specific entitlements minted for that API, or an authenticated
   authorization service with a fail-closed cache and bounded TTL.
4. Test each consumer with version 2 tokens; it must not treat missing
   permissions as authorization and must preserve strict issuer, audience,
   signature, expiry, key ID, and token-type checks.
5. Set `AUTH_LOGIN_REFRESH_RESPONSE_VERSION=2` for audited clients, then set
   `ACCESS_TOKEN_VERSION=2` for issuance. Do not change production defaults
   before that audit.

Version 1 access tokens remain accepted throughout the migration. Acceptance
must continue for at least one configured access-token TTL after the last
version 1 token is issued. Removing version 1 validation is a future breaking
release and requires a completed downstream audit; this release does not
provide a switch that can accidentally disable it.

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
- Session-creating or token-rotating operations: `X-Client-ID`, `X-Platform`,
  `X-Device-ID`, `X-Device-Type`.
- Bearer-protected operations: `X-Device-ID`, `X-User-ID`, `X-Session-ID`.
- `Authorization` is supplied through Swagger's **Authorize** dialog using
  `Bearer <signed-access-token>`; it is not duplicated as a normal parameter.
- `X-Request-ID`, `X-Correlation-ID`, and `User-Agent` are processed by shared
  request infrastructure rather than repeated on every operation.

`X-Client-Version`, `X-Device-Name`, and `Idempotency-Key` are intentionally
not advertised until a workflow actually consumes them. Sending unused values
would imply guarantees the service does not currently implement.

Security rules:

- `X-User-ID` must match the JWT `sub` claim when supplied.
- `X-Session-ID` must match the JWT `sid` claim when supplied.
- `X-Device-ID` must match persisted session metadata when both are present.
- Refresh preserves an omitted device assertion for compatibility, rejects a
  mismatching assertion with the generic authentication response, and never
  rebinds a legacy session that has no stored device ID.
- Stored session `device_id` and `device_type` values are immutable after
  session creation; clients must create a new session to establish new device
  metadata.
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

See `Architecture.md` for the detailed design and `deployment_guide.md` for production deployment guidance.
