<!-- File: Architecture.md -->

# Pharmacy Identity Service Architecture

## 1. Purpose

Pharmacy Identity Service provides centralized authentication, session management, password security, OTP verification, and database-backed authorization for the pharmacy platform.

The service is designed around the following principles:

- Authentication credentials prove identity.
- Persisted sessions determine whether authentication remains valid.
- PostgreSQL is the runtime source of truth for roles and permissions.
- Access tokens contain authentication claims, not authorization catalogs.
- Public registration cannot assign privileged roles.
- Business features own their complete workflows.
- Shared authentication infrastructure remains independent of business modules.
- Database transactions are controlled through one Unit of Work boundary.
- Security-sensitive operations fail safely and produce structured audit events.
- Secrets, credentials, tokens, OTP values, and hashes are never logged.

---

## 2. Architectural style

The application is a modular monolith organized as vertical slices.

Each vertical module owns one cohesive API capability, including:

- HTTP routes
- Request and response schemas
- Dependency composition
- Application workflow
- Persistence operations
- OpenAPI metadata

Shared authentication and security infrastructure lives under `app/auth`.

```text
app/modules/*     Business identity capabilities
app/auth/*        Shared authentication and security infrastructure
app/common/*      Reusable framework-independent contracts
app/core/*        Process-wide configuration and platform concerns
app/db/*          Database session and Unit of Work
app/models/*      SQLAlchemy ORM mappings
```

This design keeps business workflows close to their API contracts while preventing feature-specific logic from being hidden inside a generic authentication package.

---

## 3. High-level component model

```text
Client
  |
  | HTTP request
  v
FastAPI middleware
  |
  | request IDs, logging, body limits, security headers
  v
API router
  |
  v
Feature route
  |
  | typed request schema
  | feature dependency alias
  v
Feature service
  |
  | business workflow
  | policy enforcement
  v
Feature repository
  |
  | SQLAlchemy operations
  v
PostgreSQL

Supporting infrastructure:

Redis
  -> distributed rate limiting

Notification provider
  -> email and SMS delivery boundary

JWT signing keys
  -> access, refresh, and password-reset proof signing
```

PostgreSQL is authoritative for:

* Users
* User identities
* Password credentials
* Password history
* OTP challenges
* Sessions
* Refresh-token state
* Roles
* Permissions
* Role-permission assignments
* User-role assignments
* Account status
* Verification status

Redis is used for distributed rate limiting. It does not replace PostgreSQL as the identity or authorization source of truth.

---

## 4. Project organization

```text
app/
├── api/
│   ├── v1/
│   └── exception_handlers.py
│
├── auth/
│   ├── authorization/
│   ├── request_context/
│   ├── security/
│   ├── workflows/
│   ├── api_rate_limits.py
│   ├── identities.py
│   ├── normalization.py
│   ├── notifications.py
│   ├── openapi.py
│   ├── otp.py
│   ├── policies.py
│   ├── presentation.py
│   ├── route_security.py
│   ├── runtime.py
│   └── security_policy.py
│
├── common/
│   ├── auth_contracts.py
│   └── schemas.py
│
├── core/
│   ├── config.py
│   ├── logging.py
│   ├── middleware.py
│   └── request_context.py
│
├── db/
│   ├── session.py
│   └── unit_of_work.py
│
├── models/
│
├── modules/
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
│
└── utils/
    └── debug.py
```

Each feature module normally contains:

```text
routes.py
dependencies.py
schemas.py
service.py
repositories.py
openapi.py
```

---

## 5. Dependency rules

The standard dependency direction is:

```text
routes
  -> dependencies
  -> service
  -> repository
  -> SQLAlchemy session
```

Shared security infrastructure can be used by feature dependencies and services:

```text
feature dependencies
  -> app/auth request context
  -> app/auth route security
  -> app/auth rate limits

feature services
  -> app/auth token workflows
  -> app/auth password policy
  -> app/auth OTP engine
  -> app/auth authorization
```

### Allowed dependencies

* Routes may import local schemas, local dependency aliases, local OpenAPI metadata, and FastAPI transport utilities.
* Feature dependencies may compose database, service, authentication, authorization, and rate-limit dependencies.
* Services may import their local repositories and shared authentication infrastructure.
* Repositories may import SQLAlchemy and ORM models.
* `app/auth` may import shared core, database, common, and model code.
* `app/common` must remain independent of business modules.
* `app/core` must not depend on feature modules.
* Repositories may flush changes but must not commit transactions.

### Disallowed dependencies

The following structures must not be introduced:

```text
app/modules/auth/
app/auth/services/
app/auth/repositories/
app/auth/schemas/
```

Business workflows must remain inside their owning feature modules.

`app/auth` must not import implementation code from `app/modules`.

Circular imports between feature modules are not allowed.

---

## 6. Request lifecycle

A normal request passes through the following stages:

```text
Incoming HTTP request
  -> request ID and correlation ID handling
  -> trusted proxy and client IP resolution
  -> request-body size enforcement
  -> security headers
  -> structured request logging
  -> FastAPI routing
  -> request validation
  -> feature security dependency
  -> feature service
  -> Unit of Work
  -> repository operations
  -> response envelope
  -> structured completion logging
```

Errors are translated centrally into stable API responses.

Raw SQLAlchemy, JWT, validation, or internal exception messages must not be returned directly to clients.

---

## 7. Vertical module responsibilities

### `routes.py`

Routes own HTTP transport concerns:

* HTTP method and path
* Request parsing
* Response status
* Response model
* OpenAPI description
* Dependency injection
* Mapping service results into API responses

Routes must not contain:

* SQL queries
* Password hashing
* JWT creation
* Role resolution
* Transaction commits
* Complex business workflows

### `dependencies.py`

Feature dependencies compose:

* Database session
* Unit of Work
* Repositories
* Services
* Authenticated principal
* Permission requirements
* Route security policy
* Rate-limit policy

Routes should receive one named typed dependency instead of manually assembling security checks.

### `schemas.py`

Feature schemas own:

* Request bodies
* Query parameters
* Path parameter validation
* Feature-specific response DTOs

ORM models must never be returned directly as API response models.

### `service.py`

Services own:

* Use-case orchestration
* Business validation
* Policy application
* Transaction boundaries
* Coordination between repositories
* Token and session workflows
* Audit event decisions

### `repositories.py`

Repositories own:

* SQLAlchemy query construction
* Row loading
* Row locking
* Persistence mutations
* Database-specific filtering
* Pagination

Repositories must not:

* Commit transactions
* Return HTTP responses
* Decode JWTs
* Enforce route permissions
* Build FastAPI exceptions

### `openapi.py`

OpenAPI files own reusable documentation metadata for the feature:

* Tags
* Summaries
* Response descriptions
* Known error responses

---

## 8. Shared authentication kernel

`app/auth` contains infrastructure reused by multiple business modules.

### Security

`app/auth/security` owns:

* Argon2id password hashing
* Password verification
* Password rehash detection
* Domain-separated HMAC hashing
* Access-token creation
* Refresh-token creation
* Password-reset proof creation
* JWT signature and claim validation
* Signing key selection
* Key rotation
* JWKS projection

### OTP engine

The OTP engine owns:

* Cryptographically secure OTP generation
* OTP hashing
* Constant-time verification
* Expiry validation
* Attempt counting
* Cooldown handling
* Resend-window enforcement
* Purpose separation
* Replay prevention

The OTP engine does not own HTTP routes or database transactions.

### Request context

Request-context infrastructure owns:

* Bearer-token extraction
* Token validation
* Principal creation
* Session resolution
* User resolution
* Current authorization loading
* Request metadata normalization

### Authorization

Authorization infrastructure owns:

* Effective role loading
* Effective permission loading
* Assignment validity filtering
* Active and soft-delete filtering
* Permission enforcement dependencies
* Role enforcement dependencies

### Session and token workflows

Shared workflows own:

* Session creation
* Token-pair issuance
* Refresh-token hashing
* Refresh-token rotation
* Replay detection
* Session-device consistency checks
* Token expiry calculations

### Policies

Shared policies include:

* Password policy
* Password-history policy
* Account-state policy
* OTP policy
* Verification requirements
* Route security risk tiers

---

## 9. Authentication model

Authentication is based on:

```text
Signed bearer token
AND active persisted session
AND valid account state
```

A valid JWT alone is not sufficient.

Every protected request must confirm that:

* The JWT signature is valid.
* The expected algorithm is used.
* The key ID is recognized.
* The issuer is valid.
* The audience is valid.
* The token has not expired.
* The token is active according to `nbf`.
* The token type is `access`.
* The token contains a valid user subject.
* The token contains a valid session identifier.
* The persisted session exists.
* The session belongs to the token subject.
* The session is active.
* The session is not revoked.
* The session has not expired.
* The user exists.
* The user account is permitted to authenticate.

---

## 10. Access-token contract

The service uses one access-token format.

Example:

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
  "amr": [
    "password"
  ]
}
```

### Claim responsibilities

| Claim        | Purpose                                 |
| ------------ | --------------------------------------- |
| `sub`        | Authenticated user UUID                 |
| `token_type` | Distinguishes access and refresh tokens |
| `jti`        | Unique token identifier                 |
| `sid`        | Persisted session UUID                  |
| `iat`        | Token issue time                        |
| `nbf`        | Earliest valid time                     |
| `exp`        | Expiration time                         |
| `iss`        | Trusted token issuer                    |
| `aud`        | Intended token audience                 |
| `amr`        | Authentication method references        |

The access token does not contain:

* A separate `user_id` claim
* Roles
* Permissions
* Email address
* Phone number
* User profile
* Account status
* Device information
* IP address
* Contract-version fields
* Client-controlled claims

The standard `sub` claim is the only user identifier inside the token.

---

## 11. Refresh-token contract

The refresh token contains only claims required for secure rotation:

```json
{
  "sub": "5a9fcb15-f491-4ce3-93cf-f827694845c6",
  "token_type": "refresh",
  "jti": "da452a6c-6936-43bb-9ba1-dd359f250a12",
  "sid": "17157083-e4f2-48b4-9571-19e030d0ee7d",
  "fam": "9ee9ef15-a370-4235-8481-0f75c4ec60ae",
  "iat": 1785482100,
  "nbf": 1785482100,
  "exp": 1788074100,
  "iss": "pharmacy-platform-identity",
  "aud": "pharmacy-platform"
}
```

The `fam` claim identifies the refresh-token family.

Raw refresh tokens are never stored.

Only a cryptographic representation of the active refresh token is persisted.

---

## 12. Protected-request validation flow

```text
Authorization: Bearer <access-token>
  |
  v
Validate signature and key ID
  |
  v
Validate issuer and audience
  |
  v
Validate token type, expiry, and mandatory claims
  |
  v
Read user ID from sub
  |
  v
Read session ID from sid
  |
  v
Load persisted session
  |
  v
Validate ownership, expiry, and revocation
  |
  v
Load current user
  |
  v
Validate account state
  |
  v
Load effective roles and permissions from PostgreSQL
  |
  v
Apply route permission or role requirement
  |
  v
Build typed UserPrincipal
  |
  v
Execute feature workflow
```

No protected route may trust identity or permissions from request bodies or custom identity headers.

---

## 13. Header trust model

`Authorization: Bearer` is the only authentication header used by protected APIs.

### Request tracing headers

```text
X-Request-ID
X-Correlation-ID
```

These headers are optional.

When supplied, they must pass format and length validation. When omitted, the service generates values.

They are used for:

* Request tracing
* Structured logging
* Response metadata
* Audit correlation

They are not authentication inputs.

### Client and device metadata

Anonymous or rate-limited authentication operations may accept:

```text
X-Client-ID
X-Device-ID
```

Session-creating operations may additionally accept:

```text
X-Platform
X-Device-Type
```

These headers are metadata and rate-limit inputs.

They do not create an authenticated principal.

### Removed identity headers

The following headers are not supported:

```text
X-User-ID
X-Session-ID
```

The authenticated user comes from the signed `sub` claim.

The authenticated session comes from the signed `sid` claim.

Duplicating signed claims through mutable request headers adds complexity without creating a stronger security boundary.

### Forwarded client IP

`X-Forwarded-For` and similar headers are ignored unless:

* Trusted proxy handling is enabled.
* The direct network peer belongs to an explicitly configured trusted proxy range.

The service must never trust arbitrary forwarded client IP headers from public clients.

---

## 14. Declarative route security

FastAPI dependencies are the security-composition boundary.

Each protected module defines named access aliases in its own `dependencies.py`.

Example conceptual flow:

```text
AdminUserReadAccess
  -> secure_route(RouteSecurityPolicy)
  -> bearer-token validation
  -> persisted-session validation
  -> user-state validation
  -> current authorization loading
  -> required permission enforcement
  -> risk-based API rate limit
  -> typed UserPrincipal
```

Route handlers receive the validated principal and do not manually repeat authentication logic.

### Risk tiers

| Policy        | Intended use                                                |
| ------------- | ----------------------------------------------------------- |
| `STANDARD`    | Normal authenticated reads and profile operations           |
| `SENSITIVE`   | Password changes, security settings, and session revocation |
| `ADMIN_READ`  | Administrative list and detail operations                   |
| `ADMIN_WRITE` | Administrative mutations and assignments                    |
| `NONE`        | Explicitly reviewed exceptions                              |

Public route policies cannot declare role or permission requirements.

Optional authentication does not ignore invalid credentials. When a bearer token is supplied but invalid, the request is rejected instead of being silently treated as anonymous.

---

## 15. Rate limiting

Authentication workflows use payload-aware rate limits.

Examples include:

* Registration
* Password login
* OTP request
* OTP verification
* Password recovery
* Token refresh
* Refresh-token logout

Rate-limit keys may include safe normalized values such as:

* Client ID
* Device ID
* Normalized email hash
* Normalized phone hash
* OTP purpose
* Token fingerprint
* Trusted client IP

Generic authenticated routes use risk-tiered API limits.

### Backends

Supported modes are:

```text
disabled
memory
redis
```

`disabled` and `memory` are intended only for local development and tests.

Production requires Redis-backed rate limiting.

Redis failures for security-sensitive rate limits must not silently disable protection.

---

## 16. Registration architecture

### Email and password registration

```text
Validate request
  -> normalize email
  -> enforce password policy
  -> check duplicate identity
  -> create user
  -> hash and save password
  -> save password history
  -> assign server-controlled registration role
  -> create email-verification challenge when required
  -> otherwise create session and token pair
```

Public clients cannot submit role assignments.

The role assigned during self-registration must:

* Match the configured default role.
* Exist in PostgreSQL.
* Be active.
* Not be deleted.
* Be explicitly included in the self-registration allowlist.

`is_system=false` alone is not sufficient to make a role safe for public registration.

### Phone and OTP registration

```text
Validate request
  -> normalize phone number
  -> create purpose-specific OTP challenge
  -> verify destination-bound OTP
  -> reject duplicate identity
  -> create verified user
  -> assign server-controlled registration role
  -> create session
  -> issue token pair
```

Email and phone registration use the same server-controlled role policy.

---

## 17. Login architecture

### Password login

Password login supports normalized email or phone identities.

```text
Normalize identity
  -> load user and password credential
  -> perform dummy verification when identity is unknown
  -> verify password
  -> apply account-state policy
  -> update failed-attempt or success state
  -> create persisted session
  -> issue token pair
  -> record audit outcome
```

Dummy verification for unknown identities reduces timing differences between known and unknown accounts.

Failed attempts are persisted and may lock the account according to configured policy.

### OTP login

```text
Normalize phone
  -> request purpose-specific OTP
  -> verify and consume OTP
  -> validate account state
  -> create persisted session
  -> issue token pair
```

The session is created only after successful single-use OTP verification.

---

## 18. Session architecture

Sessions provide server-side control over otherwise stateless access tokens.

A session may contain:

* Session UUID
* User UUID
* Refresh-token state
* Refresh family
* Device ID
* Device type
* Client platform
* User-Agent
* Observed IP address
* Creation time
* Last-used time
* Expiration time
* Revocation state
* Revocation reason

### Session rules

* Multiple sessions per user are allowed.
* Each access token is bound to one session through `sid`.
* Each refresh token belongs to one session and one refresh family.
* Revoked sessions cannot use access or refresh tokens.
* Expired sessions cannot use access or refresh tokens.
* Deleted sessions cannot be refreshed.
* Session ownership must match JWT `sub`.
* Session ID must match JWT `sid`.
* Session lifetime must not exceed the refresh-token lifetime.

### Device metadata

A stored non-empty device ID is immutable for the lifetime of the session.

During refresh:

```text
Stored device ID exists and supplied ID matches
  -> allow refresh

Stored device ID exists and supplied ID differs
  -> reject refresh

Stored device ID exists and header is omitted
  -> preserve stored device ID

Stored device ID is empty and header is supplied
  -> do not silently rebind the session
```

The user must authenticate again to create a session with new device metadata.

A device ID is client metadata, not an independent authentication factor.

---

## 19. Refresh-token rotation

Refresh-token rotation is transactionally protected.

```text
Validate refresh JWT
  -> validate token type
  -> load session with row lock
  -> validate session and ownership
  -> compare persisted refresh-token state
  -> detect replay
  -> issue replacement access token
  -> issue replacement refresh token
  -> persist new refresh-token state
  -> commit transaction
```

### Replay detection

When a previously rotated refresh token is reused:

* The request is rejected.
* The affected refresh family or session is revoked according to policy.
* A security audit event is emitted.
* Raw tokens and token hashes are not logged.

Row locking ensures concurrent requests cannot successfully rotate the same refresh token twice.

---

## 20. Logout and session revocation

Supported session operations include:

### Current-session logout

Revokes the session represented by the current bearer token or refresh token.

### Logout from other sessions

Revokes every active session except the current session.

### Logout from all sessions

Revokes every active session owned by the authenticated user.

### Targeted session revocation

Allows a user or authorized administrator to revoke a selected session.

Session revocation must be:

* Authorized
* Transactional
* Auditable
* Immediately effective for subsequent protected requests

---

## 21. Password architecture

### Password policy

Password validation may enforce:

* Minimum length
* Character composition
* Known-password rejection
* Identity-fragment rejection
* Password-history comparison

Passwords are hashed using Argon2id.

Plaintext passwords are never stored or logged.

### Password history

Password history prevents reuse of recent passwords.

The configured history count determines how many previous password hashes are checked.

### Password change

```text
Authenticate current user
  -> verify existing password
  -> enforce password policy
  -> enforce password history
  -> update password hash
  -> save password history
  -> apply session-revocation policy
```

### Initial password setup

Initial password setup is allowed only when the account state and workflow permit it.

It uses the same password policy and history infrastructure as password change.

---

## 22. Password-reset architecture

The reset workflow never trusts a client-side flag such as:

```json
{
  "verified": true
}
```

The secure flow is:

```text
Request OTP
  -> return generic response
  -> verify and consume OTP
  -> issue short-lived signed reset proof
  -> validate and redeem reset proof once
  -> enforce password policy
  -> enforce password history
  -> update password
  -> revoke existing sessions
  -> create new session
  -> issue token pair
```

The reset proof is bound to:

* User ID
* OTP challenge ID
* Verification channel
* Destination hash
* Token type
* Issuer
* Audience
* Expiration
* Unique token ID

The reset proof is short lived and single use.

A dedicated reset-transaction table may be introduced in the future when database schema ownership permits it.

---

## 23. Authorization architecture

Runtime authorization is database-backed.

A user may have multiple role assignments.

Assignments may be:

* Global
* Scoped
* Time bound
* Active or inactive
* Soft deleted

Effective authorization requires:

```text
active user-role assignment
AND current time is after valid_from
AND current time is before valid_until
AND role is active
AND role is not deleted
AND permission is active
AND permission is not deleted
AND role-permission mapping exists
```

### Role and permission responsibilities

Runtime role and permission grants come from PostgreSQL.

Source code may define:

* Permission codes required by routes
* Initial seed manifests
* The configured self-registration role code

Source code must not grant permissions based on:

* Email address
* Hardcoded user UUID
* Client headers
* Request payloads
* JWT permission arrays
* Static role-to-permission dictionaries

### Route permission enforcement

Administrative routes require explicit permission codes.

Examples:

```text
identity.users.read
identity.users.manage
identity.roles.read
identity.roles.manage
identity.permissions.read
identity.permissions.manage
identity.user_roles.read
identity.user_roles.manage
```

Role names alone do not authorize administrative operations.

---

## 24. Current-user authorization endpoint

The canonical current-user authorization endpoint is:

```http
GET /api/v1/auth/users/me/authorization
Authorization: Bearer <access-token>
```

The endpoint:

* Requires a valid access token.
* Requires an active persisted session.
* Loads current roles and permissions from PostgreSQL.
* Applies active, validity-window, scope, and soft-delete rules.
* Returns sorted and deduplicated values.
* Does not trust authorization claims from the token.
* Does not trust authorization data from request headers.

Example response data:

```json
{
  "roles": [
    "customer"
  ],
  "permissions": [
    "commerce.orders.create",
    "commerce.orders.read",
    "customer.profiles.read"
  ]
}
```

The following redundant routes are not part of the final contract:

```text
GET /api/v1/users/me/roles
GET /api/v1/users/me/permissions
```

---

## 25. Public capabilities endpoint

The anonymous client-configuration endpoint is:

```http
GET /api/v1/auth/capabilities
```

It exposes only safe pre-authentication capabilities, such as:

* Enabled registration channels
* Enabled login channels
* Verification requirements
* Client-visible password policy
* Supported platform values
* Capability schema identifier

It must not expose:

* Role catalog
* Permission catalog
* Role-permission mappings
* Signing algorithm details
* Signing key identifiers
* OTP values
* OTP internal thresholds
* Session internals
* Lockout internals
* Database information
* Internal rate-limit configuration

The response may use safe caching through `Cache-Control` and `ETag`.

This endpoint is configuration metadata, not an authorization decision.

---

## 26. Token-pair response contract

Every token-producing public workflow returns the same token-pair response.

This includes applicable:

* Password login
* OTP login
* Registration completion
* Email verification completion
* Phone verification completion
* Password-reset completion
* Token refresh

The response contains:

* Access token
* Refresh token
* Token type
* Access-token expiry
* Refresh-token expiry
* Minimal authenticated user profile

Example user projection:

```json
{
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
```

The login and refresh user projection does not contain:

* Roles
* Permissions
* Session records
* Password metadata
* Token claims
* Internal audit fields

Administrative endpoints use dedicated administrative DTOs when additional identity information is required.

---

## 27. Transactions and concurrency

### Request sessions

One SQLAlchemy `AsyncSession` is created per request.

### Unit of Work

One Unit of Work controls transaction completion.

```text
service workflow
  -> repository operations
  -> flush when needed
  -> Unit of Work commit
```

Repositories must never call `commit()`.

The Unit of Work owns:

* Commit
* Rollback
* Transaction cleanup

### Concurrency controls

Security-sensitive operations use database concurrency controls.

Examples:

* OTP issuance serializes matching destination and purpose requests.
* OTP verification locks the active challenge.
* Refresh-token rotation locks the session row.
* Mutable records may use optimistic locking through `row_version`.
* Database uniqueness and foreign-key constraints remain the final integrity boundary.

Application-level checks do not replace database constraints.

---

## 28. Database ownership

The API service does not create or migrate database objects during normal application startup.

Database schema ownership belongs to the external migration pipeline.

The API may:

* Check connectivity.
* Verify expected schema objects.
* Fail readiness when required tables are missing.
* Seed controlled identity master data through explicit scripts.

The API must not:

* Automatically create production tables.
* Silently alter columns.
* Drop production data.
* Recreate schemas during startup.
* Hide migration failures.

Forward and rollback migration identifiers must be tracked by the external migration process.

---

## 29. Logging and audit model

Production code uses the central structured logger.

The development helper `app.utils.debug.debug` is allowed only for safe non-sensitive diagnostics.

It must:

* Produce no output in production.
* Produce no output when `DEBUG=false`.
* Route values through the central redactor.
* Accept explicit named context.
* Avoid arbitrary object dumping.

### Sensitive values

The following must never be logged:

* Plaintext passwords
* Password hashes
* OTP values
* OTP hashes
* Access tokens
* Refresh tokens
* Refresh-token hashes
* Password-reset proofs
* Verification tokens
* Authorization headers
* Cookies containing credentials
* JWT private keys
* Database passwords
* Redis passwords
* Notification credentials
* Authentication pepper

### Audit events

Security-relevant events should produce structured audit records, including:

* Successful login
* Failed login
* Account lockout
* Password change
* Password reset
* Session creation
* Session revocation
* Logout-all
* Refresh replay detection
* Administrative role assignment
* Administrative permission assignment
* User status changes

Audit events should contain identifiers, outcomes, request IDs, and correlation IDs without containing credentials.

---

## 30. Exception handling

Application exceptions are translated centrally.

The exception layer is responsible for:

* Stable HTTP status mapping
* Stable error codes
* Safe client messages
* Request and correlation metadata
* Internal logging
* Database exception translation
* Validation error translation

Raw exception messages from PostgreSQL, SQLAlchemy, Redis, JWT libraries, or cryptographic libraries must not be exposed to clients.

Authentication errors should avoid revealing whether:

* A user exists
* An email address is registered
* A phone number is registered
* A particular session exists
* A particular device ID exists
* A refresh family exists

---

## 31. Health and readiness

The service distinguishes liveness from readiness.

### Liveness

```http
GET /health/live
```

Liveness confirms that the process is running.

It should not fail only because an external dependency is temporarily unavailable.

### Readiness

```http
GET /health/ready
```

Readiness may verify:

* PostgreSQL connectivity
* Required identity schema objects
* Redis connectivity when configured
* Process initialization state

A container should receive production traffic only when readiness succeeds.

Dependency health checks must use bounded timeouts.

---

## 32. Infrastructure model

The Docker image contains only the Python API service.

PostgreSQL and Redis are external services.

```text
FastAPI container
  |
  +-- PostgreSQL
  |
  +-- Redis
  |
  +-- Notification provider
  |
  +-- Secret manager
```

The service container should run:

* As a non-root user
* With a read-only filesystem
* With a writable temporary filesystem only where required
* With `no-new-privileges`
* With bounded logs
* With health checks
* Without embedded production secrets

Production secrets must be injected through the deployment platform or secret manager.

---

## 33. Security boundaries

### Authentication boundary

The bearer token and persisted session prove authenticated identity.

### Authorization boundary

Current database-backed roles and permissions decide access.

### Database boundary

PostgreSQL constraints and transactions preserve identity integrity.

### Rate-limit boundary

Redis coordinates limits across API replicas.

### Notification boundary

The notification adapter sends email and SMS without exposing provider details to feature modules.

### Deployment boundary

TLS termination, secret injection, network policy, and trusted proxies are controlled by the deployment platform.

---

## 34. Explicit scope boundaries

The following workflows are not active in the current release:

* Multi-factor authentication beyond existing single-channel OTP flows
* API-client authentication
* Machine-to-machine OAuth
* Social login
* Enterprise identity federation
* SAML
* OpenID Connect provider functionality
* Token introspection for external services
* Administrative impersonation, unless already implemented and explicitly reviewed

Existing ORM mappings or enum values related to future features may remain for database compatibility.

They must not be treated as active merely because a model exists.

Inactive features must not have:

* Public routes
* Runtime service wiring
* Token types
* Environment settings
* Rate-limit policies
* Notification flows
* Authorization bypasses

---

## 35. Architectural decisions

### PostgreSQL authorization instead of token permissions

Roles and permissions are not embedded in access tokens because:

* They become stale after RBAC changes.
* Large permission arrays increase token size.
* Tokens may be inspected by clients.
* Permission revocation would otherwise wait for token expiry.
* Consumers may incorrectly treat token claims as permanent authorization.

### Persisted sessions with JWT access tokens

Persisted sessions allow:

* Immediate logout
* Session revocation
* Device-session management
* Refresh replay detection
* Account-state enforcement
* Server-side invalidation before access-token expiry

### Server-controlled public-registration role

Public clients cannot assign their own roles because role selection is an authorization decision, not registration data.

### No custom user or session identity headers

`X-User-ID` and `X-Session-ID` are excluded because signed JWT claims already provide authenticated identity and session context.

### Feature-owned workflows

Registration, login, password management, and administration remain separate vertical slices to reduce coupling and make ownership clear.

### External migration ownership

Database migrations remain outside API startup to prevent accidental production schema modification and to keep rollback ownership explicit.

---

## 36. Quality expectations

The architecture is protected through:

* Unit tests
* Contract tests
* PostgreSQL integration tests
* JWT claim tests
* Authorization tests
* Session and refresh tests
* Header contract tests
* OpenAPI contract tests
* Static analysis
* Formatting checks
* Dependency audits
* Secret scanning
* Container startup validation

Required verification commands are documented in:

* [`README.md`](README.md)
* [`deployment_guide.md`](deployment_guide.md)
* [`script_commands.md`](script_commands.md)

The complete HTTP route inventory is documented in:

* [`ENDPOINT_INVENTORY.md`](ENDPOINT_INVENTORY.md)