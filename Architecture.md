<!-- File: Architecture.md -->

# Authentication Architecture

## Architectural style

The identity service is a modular monolith organized as vertical slices. A vertical slice owns the HTTP contract, application workflow, persistence adapter, and OpenAPI metadata for one cohesive API family.

```text
app/modules/*     public identity capabilities
app/auth/*        shared authentication infrastructure
app/common/*      framework-independent shared contracts
app/core/*        process-wide platform concerns
app/db/*          database session and Unit of Work
app/models/*      externally migrated ORM mappings
```

## Dependency rule

```text
routes -> service -> repository -> SQLAlchemy session
   |          |
 schemas   app/auth shared infrastructure
```

Allowed dependencies:

- Routes import their local schemas, local dependency aliases, local OpenAPI
  metadata, and transport-level framework utilities.
- Each feature's `dependencies.py` constructs services and composes shared
  request/security dependencies; routes import the resulting typed aliases.
- Services import their local repository and schemas plus shared infrastructure.
- Repositories import SQLAlchemy and ORM models.
- `app/auth` imports no business module.
- `app/common` imports no business module.
- The Unit of Work is the only commit and rollback boundary.

Disallowed structures:

```text
app/modules/auth/
app/auth/services/
app/auth/repositories/
app/auth/schemas/
```

The removed directories previously caused business logic to live behind module-level re-export files. The final structure contains the implementation directly inside each owning module.

## Vertical modules

Each module contains these architectural surfaces:

```text
routes.py
dependencies.py
schemas.py
service.py
repositories.py
openapi.py
```

The current modules are:

- `registration`
- `email_verification`
- `login`
- `token_management`
- `session_management`
- `password_management`
- `current_user`
- `admin_users`
- `admin_roles`
- `admin_permissions`
- `admin_user_roles`

## Shared authentication kernel

`app/auth` contains only cross-cutting identity infrastructure:

- JWT creation, validation, key rotation, and JWKS projection
- Argon2 password policy, hashing, verification, and rehash detection
- Domain-separated HMAC hashing
- Persistence-agnostic OTP generation and verification
- Access/refresh token pair and session creation
- Account, OTP, and password-history policies
- Typed authentication headers
- Request metadata normalization
- Authenticated user-principal resolution
- Persisted session verification
- Role and permission dependencies
- Effective authorization-claim loading
- Declarative route-security policies and dependency composition
- Authentication and general API rate-limit key construction
- Notification integration boundary
- Safe user projection helpers

Shared response DTOs that are byte-for-byte identical across modules live in `app/common/auth_contracts.py`. Request schemas and feature-specific responses remain in the owning module.

## Header security model

`X-User-ID`, `X-Session-ID`, and `X-Device-ID` are assertions, not credentials.

Protected request validation follows this order:

```text
Authorization bearer token
  -> signature, issuer, audience, expiry, key id, token type
  -> JWT user and session identifiers
  -> optional header consistency checks
  -> persisted session ownership, expiry, revocation, and device binding
  -> current user account state
  -> fresh roles and permissions when enabled
  -> endpoint permission or role requirement
```

This prevents spoofed identity headers from escalating privileges.

For access-token version 2, persisted-session validation and current database
authorization resolution are mandatory regardless of the general refresh
configuration. A version 2 JWT permission field is invalid; it cannot become an
authorization source merely because it is correctly signed.

Routes inject one of three narrow request-context profiles instead of exposing
every possible metadata header on every operation:

- anonymous rate limits use client and stable-device identifiers;
- session creation/rotation additionally uses platform and device type;
- protected routes use optional device, user, and session consistency assertions.

The bearer token is declared as the OpenAPI `BearerAuth` security scheme, so
Swagger collects it through **Authorize** and FastAPI resolves it before the
service is called. Metadata headers never replace that signed token.

## Route-security composition

FastAPI dependencies are the security composition boundary. Each protected
module defines named access aliases in its local `dependencies.py`; routes
inject those aliases instead of manually repeating authentication,
authorization, and generic API rate-limiting calls.

```text
module access alias
  -> secure_route(RouteSecurityPolicy)
  -> bearer principal and persisted-session validation
  -> fresh permission/role checks
  -> APIRateLimits risk tier
  -> typed UserPrincipal
```

The route policy is immutable metadata and supports `STANDARD`, `SENSITIVE`,
`ADMIN_READ`, `ADMIN_WRITE`, and explicit `NONE` rate tiers. Public policies
use an optional principal, but cannot declare role or permission requirements.
A supplied invalid bearer token is still rejected; optional authentication
does not silently downgrade invalid credentials to anonymous access.

Authentication workflows keep their payload-aware limits. Login, OTP,
registration, password reset, refresh, and refresh-token logout need identity,
purpose, or token-fingerprint keys that a generic route policy cannot safely
infer. The generic API limiter is used for authenticated profile,
administrative, password, logout-all, and session routes.

The rate-limit backend may be disabled in development and tests. Production
startup rejects a disabled backend and requires Redis. Authorization has no
global production bypass; tests use dependency overrides where isolation is
required.

## Registration flows

### Email and password

```text
normalize email
  -> enforce password policy
  -> reject duplicate identity
  -> create user and password history
  -> assign default role
  -> issue email-verification OTP when required
  -> otherwise create session and token pair
```

### Phone and OTP

```text
normalize phone
  -> issue registration OTP
  -> verify destination-bound challenge
  -> reject duplicate identity
  -> create verified user
  -> assign default role
  -> create session and token pair
```

## Login flows

Password login supports an email or phone identity. It performs a dummy password verification for unknown identities to reduce timing-based enumeration. Failed attempts are persisted and can lock the account according to policy.

Phone OTP login issues a purpose-specific challenge and creates a session only after successful, single-use verification.

## Sessions and token rotation

- Access tokens are short lived.
- Refresh tokens are persisted only as hashes.
- Every refresh token belongs to a persisted session and token family.
- Rotation locks the session row.
- Reuse of an already rotated refresh token revokes the complete family.
- Users can revoke the current session, all other sessions, all sessions, or one selected session.
- Multiple device sessions are allowed.
- A non-empty device ID and device type are immutable for the lifetime of a
  session. Refresh may observe but may not replace either value.
- IP address and User-Agent are observational metadata, not authentication
  factors. They may be refreshed after successful token validation and do not
  override device binding.
- Refresh replay and explicit session revocation emit structured audit events
  containing identifiers and outcomes, never raw tokens or token hashes.

## Password reset

The reset flow does not trust a client-side `verified=true` flag.

```text
request OTP
  -> return generic response
  -> verify and consume OTP
  -> issue short-lived signed reset proof
  -> redeem proof once
  -> enforce password policy and history
  -> update password
  -> revoke existing sessions
  -> mark reset proof state as redeemed
  -> create a new session and token pair
```

The reset proof is bound to user ID, OTP challenge ID, channel, destination hash, expiry, JWT type, issuer, audience, and unique token ID.

A dedicated reset-transaction table is the preferred future migration when schema ownership permits it.

## Authorization

A user can hold multiple active role assignments. Assignments can be global or scoped and can have validity windows.

Effective permission calculation requires:

```text
active user-role assignment
AND current time inside valid_from and valid_until
AND non-deleted role
AND non-deleted permission
AND existing role-permission mapping
```

Administrative routes require permission codes through reusable dependencies. Role names alone do not authorize administrative actions.

The canonical self-service authorization contract is:

```text
GET /api/v1/auth/users/me/authorization
  -> valid access token
  -> active persisted session
  -> effective database authorization query
  -> sorted, deduplicated roles and permissions
```

The older `/api/v1/users/me/roles` and
`/api/v1/users/me/permissions` routes remain temporarily and are deprecated in
OpenAPI. They delegate to the same application service and therefore cannot
drift from the consolidated result.

### Versioned profile and token contracts

Version 1 login/refresh responses retain the historical `UserResponse`,
including roles and permissions. Version 2 responses use a separate minimal
profile DTO; authorization fields do not conditionally disappear from one
schema. Administrative and registration responses remain their existing
version 1 contracts during this migration.

Version 1 access tokens retain `roles` and `permissions`. Newly issued tokens
carry `ver: 1`, while tokens issued before versioning and lacking `ver` remain
valid as legacy version 1. Version 2 contains registered JWT claims, `sid`,
`amr`, and `ver: 2`; it never contains global permissions. Coarse role hints
are optional configuration and are replaced by current database roles before
this service evaluates authorization.

Full global permission arrays are removed from future tokens because they
inflate headers, become stale after an RBAC change, and encourage downstream
services to treat a broad identity token as an audience-specific authorization
decision. Browser/UI permission state is likewise only a display aid.
Downstream services should use narrowly scoped, audience-specific entitlements
or an authenticated authorization service. An anonymous permission catalog
would disclose internal capability names and, more importantly, would provide
no trustworthy user-specific authorization decision, so it must not be used.

## Transactions and concurrency

- One `AsyncSession` is created per request.
- One Unit of Work wraps each application workflow.
- Repositories never call `commit()`.
- OTP issuance serializes concurrent requests for a destination and purpose.
- OTP verification locks the challenge row.
- Refresh rotation locks the session row.
- Mutable records use optimistic locking through `row_version`.
- PostgreSQL constraints remain the final integrity boundary.

## Logging and debugging

Production code uses the central structured logger. The `app.utils.debug.debug` helper is available only for non-sensitive development diagnostics.

The helper:

- emits nothing in production
- emits nothing when `DEBUG=false`
- routes context through the central redactor
- accepts a message and explicitly named context only
- prevents arbitrary `print(*objects)` logging

Administrative security actions and login attempts use production-visible audit logging. Plaintext passwords, OTPs, refresh tokens, access tokens, reset proofs, authorization headers, secrets, and hashes must never be logged.

## Scope boundaries

No MFA or API-client authentication workflow is implemented in this release. Legacy ORM mappings and enum values supplied by the existing identity schema are retained to avoid an unrequested database-contract change. They are not wired into routes, runtime dependencies, services, repositories, settings, or token generation.

The API does not create or migrate database objects. Schema changes remain the responsibility of the external migration pipeline.
