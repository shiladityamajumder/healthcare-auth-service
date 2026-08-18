# Authentication Service API Reference

**Service:** `pharmacy_identity_service`  
**API version:** `v1`  
**Default versioned base path:** `/api/v1`  
**Contract style:** JSON over HTTPS, camelCase fields, canonical response envelope  
**Last verified against source:** 2026-08-17

This document is the consumer-facing contract for the authentication and identity service. It is derived from the implemented FastAPI routes, Pydantic schemas, security dependencies, service rules, middleware, and centralized exception handlers in this repository.

It explains not only what to send, but when each operation should be used, which credential is accepted, which permission is required, what a successful response contains, and how clients should handle failures.

> **Contract authority:** generated OpenAPI (`/openapi.json`) is the machine-readable contract. This file is the human-readable integration guide. When a future code change alters an endpoint, schema, or security policy, both contracts must be updated in the same pull request.

---

## 1. Integration overview

### 1.1 Environments and base URL

The application exposes system routes at the host root and business routes below the configurable `API_V1_STR` value, which defaults to `/api/v1`.

```text
https://<identity-service-host>/api/v1
```

Example development URL:

```text
http://localhost:5555/api/v1
```

Interactive documentation is available only when `DOCS_ENABLED=true`:

| Resource | Path |
|---|---|
| Swagger UI | `/docs` |
| ReDoc | `/redoc` |
| OpenAPI JSON | `/openapi.json` |

Production configuration intentionally disables those three endpoints. This Markdown reference should therefore be available to API consumers independently of the running service.

### 1.2 Media type and field naming

- Send request bodies as `Content-Type: application/json`.
- Send `Accept: application/json` where an explicit accept type is required by the client platform.
- JSON properties and URL/query parameters use **camelCase**.
- Timestamps use ISO 8601 date-time strings and should be interpreted as timezone-aware values.
- Identifiers are UUID strings.
- Unknown request-body properties are rejected. Request schemas use `extra="forbid"`; clients must not send undocumented fields.
- `null`, omitted, and empty values are not interchangeable. PATCH behavior is described per endpoint.

### 1.3 Authentication modes

The service uses three distinct security modes. Do not substitute one credential type for another.

| Mode | Credential | Where used | Important behavior |
|---|---|---|---|
| Public | None | Registration, login, OTP request/verification, capabilities, JWKS, health | Optional metadata headers support rate limiting and session creation; they never identify or authorize a user. |
| Refresh-token protected | `refreshToken` in JSON body | Token refresh and current-session logout | A bearer access token is not required. The refresh token is validated by token type and persisted session state. |
| Bearer protected | `Authorization: Bearer <accessToken>` | Sessions, password change/set, current user, all admin APIs | The signed access token, persisted session, account state, and current database authorization are validated on every request. |

Bearer example:

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InByaW1hcnkiLCJ0eXAiOiJKV1QifQ...
```

The service does **not** accept `X-User-ID`, `X-Session-ID`, `X-Role`, `X-Roles`, `X-Permission`, or `X-Permissions` as identity or authorization inputs. Roles and permissions are loaded from PostgreSQL for the authenticated user. Supplying invented identity headers cannot grant access.

### 1.4 Token handling rules

- `accessToken` is a short-lived bearer credential. The default lifetime is 15 minutes and is configurable from 1 to 60 minutes.
- `refreshToken` is a rotating, session-bound credential. The default lifetime is 30 days and is configurable from 1 to 365 days.
- Refresh rotation returns a new access token **and** refresh token. After a successful refresh, atomically replace the stored pair and never reuse the old refresh token.
- Refresh-token reuse revokes the token family and returns `AUTH_REFRESH_TOKEN_REUSE`.
- Password change, initial password setup, and password reset revoke older sessions and issue one replacement token pair.
- Store tokens only in a platform-appropriate secure credential store. Never log them, put them in URLs, analytics events, error reports, or localStorage in a high-risk browser application.
- The server returns tokens in JSON. Browser applications should normally exchange them through a trusted backend-for-frontend if HttpOnly cookie storage is required.

### 1.5 Request metadata headers

All metadata headers are optional. They improve traceability, rate-limit accuracy, and session display, but do not authenticate the request.

| Header | Maximum | Accepted on | Purpose |
|---|---:|---|---|
| `X-Request-ID` | UUID format | All routes | End-to-end request identifier. Invalid values return `400 INVALID_REQUEST_ID`. The server generates one when omitted. |
| `X-Correlation-ID` | UUID format | All routes | Groups related calls. Invalid values return `400 INVALID_CORRELATION_ID`. Defaults to the request ID. |
| `X-Client-ID` | 128 chars | Public rate-limited flows, session-creating flows, refresh/logout | Stable application-installation or client identifier used as a rate-limit dimension. Do not put secrets or user PII here. |
| `X-Platform` | 16 chars | Session-creating flows | One of `web`, `android`, `ios`, `service`; persisted with session context when applicable. |
| `X-Device-ID` | 255 chars | Public rate-limited flows, session-creating flows, refresh/logout | Rate-limit dimension; persisted at session creation. On refresh, if both stored and supplied values exist, they must match. |
| `X-Device-Type` | 32 chars | Session-creating flows | Normalized device category persisted with the created session, for example `browser` or `mobile`. |
| `User-Agent` | 512 chars | All routes | Captured as bounded session/request metadata where relevant. |

Session-creating operations are email registration when verification is disabled, phone registration verification, email verification, password login, phone OTP login verification, password reset, password change, and initial password setup.

### 1.6 Response headers

Every normal response receives:

| Header | Meaning |
|---|---|
| `X-Request-ID` | Effective request UUID. Include it in support and incident reports. |
| `X-Correlation-ID` | Effective correlation UUID. Propagate it to downstream service calls. |
| `X-API-Version` | Effective API version, normally `v1`. |

Security middleware also sets conservative headers such as `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`. The capabilities endpoint overrides caching with `Cache-Control: public, max-age=300` and an `ETag`.

### 1.7 Rate limiting

Rate limits are configuration-driven. The defaults below explain the current operating contract; deployment values may be stricter.

| Policy | Default quota/window | Applied to |
|---|---:|---|
| Registration | 5 / 600 s | Email registration |
| Login | 10 / 300 s | Password login |
| OTP request | 5 / 600 s | Phone registration/login OTP, email verification OTP |
| OTP verify | 10 / 300 s | OTP confirmation routes |
| Password reset request | 5 / 900 s | Forgot-password flow |
| Refresh | 30 / 60 s | Refresh-token rotation |
| Refresh logout | 30 / 60 s | Logout by refresh token |
| Standard | 120 / 60 s | Authenticated read routes |
| Sensitive | 30 / 60 s | Authenticated security mutations |
| Admin read | 120 / 60 s | Permission-protected administration reads |
| Admin write | 20 / 60 s | Permission-protected administration writes |

Rate-limit keys use hashed identity, token fingerprint, user, IP, client, and/or device dimensions. A `429` response includes `Retry-After` and `error.details.retryAfterSeconds`. Clients must back off for at least that duration; do not retry in a tight loop.

---

## 2. Canonical response contract

### 2.1 Success envelope

Except for `304 Not Modified`, every successful JSON response uses this envelope:

```json
{
  "success": true,
  "data": {},
  "error": null,
  "meta": {
    "requestId": "0c50f15a-373f-42d3-b1ae-3d90a415cd91",
    "correlationId": "9182b204-cb82-4ddc-a49d-b07743388ed6",
    "apiVersion": "v1",
    "timestamp": "2026-08-17T12:00:00Z",
    "pagination": null
  }
}
```

The endpoint examples below show the request body and the value inside `data`. Wrap that data in the envelope above unless a section explicitly documents a different response.

### 2.2 Paginated success envelope

Only the admin user list is paginated in the current API.

```json
{
  "success": true,
  "data": {
    "users": []
  },
  "error": null,
  "meta": {
    "requestId": "0c50f15a-373f-42d3-b1ae-3d90a415cd91",
    "correlationId": "9182b204-cb82-4ddc-a49d-b07743388ed6",
    "apiVersion": "v1",
    "timestamp": "2026-08-17T12:00:00Z",
    "pagination": {
      "totalCount": 42,
      "limit": 20,
      "offset": 0,
      "hasNext": true
    }
  }
}
```

### 2.3 Error envelope

All handled failures use this envelope:

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "REQUEST_VALIDATION_ERROR",
    "message": "The request contains invalid input.",
    "details": [
      {
        "field": "body.email",
        "message": "value is not a valid email address",
        "type": "value_error"
      }
    ]
  },
  "meta": {
    "requestId": "0c50f15a-373f-42d3-b1ae-3d90a415cd91",
    "correlationId": "9182b204-cb82-4ddc-a49d-b07743388ed6",
    "apiVersion": "v1",
    "timestamp": "2026-08-17T12:00:00Z",
    "pagination": null
  }
}
```

Do not branch client behavior on the human-readable `message`. Use the HTTP status plus stable `error.code`. Treat `details` as optional and forward-compatible.

### 2.4 Common HTTP statuses and error codes

| HTTP | Common code | Client meaning/action |
|---:|---|---|
| 400 | `BAD_REQUEST`, `INVALID_REQUEST_ID`, `INVALID_CORRELATION_ID`, `INVALID_CONTENT_LENGTH`, `UNTRUSTED_HOST` | Correct malformed transport input; do not retry unchanged. |
| 401 | `AUTHENTICATION_REQUIRED`, `AUTH_INVALID_CREDENTIALS`, `AUTH_ACCOUNT_LOCKED`, `AUTH_ACCOUNT_DISABLED`, `AUTH_OTP_EXPIRED`, `AUTH_OTP_INVALID`, `AUTH_OTP_ATTEMPTS_EXCEEDED`, `AUTH_OTP_ALREADY_USED`, `AUTH_SESSION_REVOKED`, `AUTH_REFRESH_TOKEN_REUSE` | Authentication proof is absent or unusable. Clear invalid credentials; restart the appropriate login/recovery flow. A `WWW-Authenticate: Bearer` header is returned for application authentication errors. |
| 403 | `PERMISSION_DENIED` | The authenticated account is valid but lacks a required permission/role. Do not refresh-loop; hide or disable the unauthorized operation and request access through an administrative process. |
| 404 | `RESOURCE_NOT_FOUND`, `ROUTE_NOT_FOUND` | Resource is absent, deleted, outside caller ownership, or feature route is disabled. |
| 405 | `METHOD_NOT_ALLOWED` | Use the documented HTTP method. |
| 409 | `RESOURCE_CONFLICT`, `AUTH_IDENTITY_ALREADY_EXISTS`, `PERMISSION_CODE_ALREADY_EXISTS`, `CONCURRENT_UPDATE_CONFLICT` | Current resource state conflicts with the requested mutation. Reload or resolve the conflict before retrying. |
| 413 | `PAYLOAD_TOO_LARGE` | Body exceeded `MAX_REQUEST_BODY_BYTES` (2 MiB by default). Reduce the request. |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Send JSON with the correct content type. |
| 422 | `REQUEST_VALIDATION_ERROR`, `VALIDATION_ERROR` | Field/schema or domain-policy validation failed. Display field-safe feedback and correct input. |
| 429 | `RATE_LIMIT_EXCEEDED` | Wait for `Retry-After`; retry with exponential backoff and jitter. |
| 500 | `INTERNAL_SERVER_ERROR`, `DATABASE_ERROR` | Unexpected server failure. Retry only where the operation is safely repeatable; report request ID. |
| 503 | `SERVICE_NOT_READY`, `DEPENDENCY_HEALTH_CHECK_FAILED`, `DATABASE_UNAVAILABLE`, `INFRASTRUCTURE_UNAVAILABLE`, `RATE_LIMIT_BACKEND_ERROR` | Required infrastructure is unavailable. Use bounded backoff/circuit breaking. |
| 504 | `OPERATION_TIMEOUT` | A bounded operation timed out. Retry only if the operation is idempotent or application state has been reconciled. |

### 2.5 Validation and password policy

The default password policy requires:

- at least 12 characters (deployment configurable);
- at least three of uppercase, lowercase, number, and symbol;
- no leading/trailing whitespace or null character;
- no meaningful email username or phone-number fragment;
- no reuse of the current/recent password during change/reset (history depth defaults to 5).

The transport schema permits up to 128 characters; the stronger policy is evaluated by the service and returns `422 VALIDATION_ERROR`.

OTP codes are exactly six digits. Defaults are a 300-second lifetime, five verification attempts, a 60-second resend cooldown, and five resends per 3,600-second window. `developmentOtp` is `null` unless explicitly enabled in a non-production environment.

---

## 3. Endpoint catalogue and access matrix

Legend: **Public** = no token; **Refresh body** = refresh token in JSON; **Bearer** = access token required.

| Method | Path | Security | Permission | Primary use |
|---|---|---|---|---|
| GET | `/` | Public | — | Service discovery descriptor |
| GET | `/health/live` | Public | — | Process liveness |
| GET | `/health/ready` | Public | — | Traffic readiness and PostgreSQL/schema check |
| GET | `/health/deep` | Public | — | Optional detailed dependency diagnostics |
| GET | `/api/v1/auth/capabilities` | Public | — | Configure login/registration UI safely |
| GET | `/api/v1/auth/.well-known/jwks.json` | Public | — | Obtain RS256 JWT verification keys |
| POST | `/api/v1/auth/register/email` | Public | — | Create email/password account |
| POST | `/api/v1/auth/register/phone/request-otp` | Public | — | Begin phone registration |
| POST | `/api/v1/auth/register/phone/verify-otp` | Public | — | Complete phone registration and create session |
| POST | `/api/v1/auth/email-verification/request` | Public | — | Issue/resend email verification OTP |
| POST | `/api/v1/auth/email-verification/verify` | Public | — | Verify email and create session |
| POST | `/api/v1/auth/login/password` | Public | — | Password login by email or phone |
| POST | `/api/v1/auth/login/phone/request-otp` | Public | — | Begin phone OTP login |
| POST | `/api/v1/auth/login/phone/verify-otp` | Public | — | Complete phone OTP login |
| POST | `/api/v1/auth/token/refresh` | Refresh body | — | Rotate session token pair |
| POST | `/api/v1/auth/logout` | Refresh body | — | Revoke refresh-token session |
| POST | `/api/v1/auth/logout/others` | Bearer | — | Preserve current session; revoke other sessions |
| POST | `/api/v1/auth/logout/all` | Bearer | — | Revoke every current-user session |
| GET | `/api/v1/auth/sessions` | Bearer | — | List current-user active sessions |
| DELETE | `/api/v1/auth/sessions/{sessionId}` | Bearer | — | Revoke one owned session |
| POST | `/api/v1/auth/password/forgot` | Public | — | Begin password recovery |
| POST | `/api/v1/auth/password/reset/verify-otp` | Public | — | Exchange OTP for reset proof |
| POST | `/api/v1/auth/password/reset` | Public reset proof | — | Set recovered password and create replacement session |
| PUT | `/api/v1/auth/password` | Bearer | — | Change an existing password |
| POST | `/api/v1/auth/password` | Bearer | — | Add first password to OTP-only account |
| GET | `/api/v1/auth/users/me/authorization` | Bearer | — | Read current effective global roles/permissions |
| GET | `/api/v1/users/me` | Bearer | — | Read current identity/profile |
| PATCH | `/api/v1/users/me` | Bearer | — | Update current preferences/profile |
| GET | `/api/v1/admin/users` | Bearer | `identity.users.read` | List/search users |
| GET | `/api/v1/admin/users/{userId}` | Bearer | `identity.users.read` | Read user and effective authorization |
| PATCH | `/api/v1/admin/users/{userId}/status` | Bearer | `identity.users.manage` | Change account status |
| POST | `/api/v1/admin/users/{userId}/logout-all` | Bearer | `identity.users.manage` | Administratively revoke all user sessions |
| GET | `/api/v1/admin/roles` | Bearer | `identity.roles.read` | List active roles |
| POST | `/api/v1/admin/roles` | Bearer | `identity.roles.manage` | Create custom role |
| GET | `/api/v1/admin/roles/{roleId}` | Bearer | `identity.roles.read` | Read role |
| PATCH | `/api/v1/admin/roles/{roleId}` | Bearer | `identity.roles.manage` | Update role |
| DELETE | `/api/v1/admin/roles/{roleId}` | Bearer | `identity.roles.manage` | Soft-delete custom role |
| GET | `/api/v1/admin/permissions` | Bearer | `identity.permissions.read` | List active permission definitions |
| POST | `/api/v1/admin/permissions` | Bearer | `identity.permissions.manage` | Create permission definition |
| GET | `/api/v1/admin/permissions/{permissionId}` | Bearer | `identity.permissions.read` | Read permission definition |
| PATCH | `/api/v1/admin/permissions/{permissionId}` | Bearer | `identity.permissions.manage` | Update permission definition |
| DELETE | `/api/v1/admin/permissions/{permissionId}` | Bearer | `identity.permissions.manage` | Soft-delete permission definition |
| GET | `/api/v1/admin/roles/{roleId}/permissions` | Bearer | `identity.permissions.read` | Read complete active role policy |
| PUT | `/api/v1/admin/roles/{roleId}/permissions` | Bearer | `identity.permissions.manage` | Atomically replace complete role policy |
| GET | `/api/v1/admin/users/{userId}/roles` | Bearer | `identity.user_roles.read` | List global/scoped role assignments |
| POST | `/api/v1/admin/users/{userId}/roles` | Bearer | `identity.user_roles.manage` | Assign a role |
| PATCH | `/api/v1/admin/users/{userId}/roles/{userRoleId}` | Bearer | `identity.user_roles.manage` | Update assignment scope/window/state |
| DELETE | `/api/v1/admin/users/{userId}/roles/{userRoleId}` | Bearer | `identity.user_roles.manage` | Remove assignment |

---

## 4. Shared response data models

These are reusable `data` objects referenced by endpoint sections.

### 4.1 Authenticated user

```json
{
  "id": "b9c2e6c1-7485-413f-a232-b02f6d1950fa",
  "email": "user@example.com",
  "emailVerified": true,
  "phoneCountryCode": "+91",
  "phoneNumberMasked": "******3210",
  "phoneVerified": true,
  "status": "active",
  "preferredLocale": "en-IN",
  "timezone": "Asia/Kolkata",
  "displayName": "Asha Sen",
  "profile": {
    "firstName": "Asha",
    "lastName": "Sen",
    "preferredName": "Asha",
    "avatar": {
      "id": "119432a7-48a1-4cbe-975b-7787f2aa811c",
      "url": "https://cdn.example.com/public/avatar.jpg"
    }
  }
}
```

`email`, phone fields, `profile`, and `profile.avatar` may be `null`. Raw phone numbers, password hashes, internal file keys, and authorization lists are deliberately absent.

### 4.2 Token pair

```json
{
  "accessToken": "<access-jwt>",
  "refreshToken": "<refresh-jwt>",
  "tokenType": "Bearer",
  "accessExpiresAt": "2026-08-17T12:15:00Z",
  "refreshExpiresAt": "2026-09-16T12:00:00Z",
  "user": {
    "id": "b9c2e6c1-7485-413f-a232-b02f6d1950fa",
    "email": "user@example.com",
    "emailVerified": true,
    "phoneCountryCode": null,
    "phoneNumberMasked": null,
    "phoneVerified": false,
    "status": "active",
    "preferredLocale": "en-IN",
    "timezone": "Asia/Kolkata",
    "displayName": "Asha Sen",
    "profile": null
  }
}
```

### 4.3 OTP challenge

```json
{
  "accepted": true,
  "challengeId": "ca4e81f0-bc8d-493c-a409-685527cb8f3d",
  "expiresAt": "2026-08-17T12:05:00Z",
  "retryAfterSeconds": 60,
  "developmentOtp": null
}
```

### 4.4 Role, permission, and assignment

Role:

```json
{
  "id": "264920dd-2af4-4b1c-9865-a78a0e47b97a",
  "code": "support_agent",
  "name": "Support Agent",
  "description": "Customer support access",
  "isSystem": false,
  "createdAt": "2026-08-17T11:00:00Z",
  "updatedAt": "2026-08-17T11:00:00Z"
}
```

Permission:

```json
{
  "id": "f1081e64-5c33-49bd-b8c2-2cffbc49677a",
  "code": "identity.users.read",
  "resource": "identity.users",
  "action": "read",
  "description": "Read identity users",
  "createdAt": "2026-08-17T11:00:00Z",
  "updatedAt": "2026-08-17T11:00:00Z"
}
```

User-role assignment:

```json
{
  "id": "1e58f27b-256d-46a1-84d2-66b708ba7c6f",
  "userId": "b9c2e6c1-7485-413f-a232-b02f6d1950fa",
  "roleId": "264920dd-2af4-4b1c-9865-a78a0e47b97a",
  "roleCode": "support_agent",
  "roleName": "Support Agent",
  "scopeType": "tenant",
  "scopeId": "54a18d98-88ef-442b-a570-f97fbc487e04",
  "validFrom": "2026-08-17T00:00:00Z",
  "validUntil": null,
  "isActive": true,
  "createdAt": "2026-08-17T11:00:00Z",
  "updatedAt": "2026-08-17T11:00:00Z"
}
```

---

## 5. System and discovery endpoints

### 5.1 Service descriptor

`GET /`

Use this lightweight public endpoint for service discovery and operator diagnostics. It is not a readiness signal; use `/health/ready` before sending production traffic.

**Token:** not required  
**Body:** none  
**Success:** `200 OK`

```json
{
  "service": "pharmacy_identity_service",
  "version": "1.0.0",
  "apiBase": "/api/v1",
  "documentation": "/docs",
  "health": {
    "liveness": "/health/live",
    "readiness": "/health/ready",
    "deep": "/health/deep"
  }
}
```

`documentation` or `health.deep` may be `null` when disabled. Unexpected failures use `500 INTERNAL_SERVER_ERROR`.

### 5.2 Liveness

`GET /health/live`

Use for a container/process liveness probe. It intentionally does not query PostgreSQL. A successful response proves that the HTTP process can answer, not that it can serve authentication traffic.

**Token:** not required  
**Body:** none  
**Success:** `200 OK`

```json
{"status": "alive"}
```

### 5.3 Readiness

`GET /health/ready`

Use for load-balancer/Kubernetes readiness. It checks lifespan readiness and performs a bounded PostgreSQL check, including required schema verification when configured.

**Token:** not required  
**Body:** none  
**Success:** `200 OK`

```json
{
  "ready": true,
  "checks": {
    "postgresql": {
      "healthy": true,
      "schemaReady": true
    }
  }
}
```

| Failure | Meaning |
|---|---|
| `503 SERVICE_NOT_READY` | Lifespan initialization is incomplete, PostgreSQL is unhealthy, or the required schema is unavailable. |

Readiness probes should retry on their normal platform schedule. Application clients should not call this endpoint before every request.

### 5.4 Deep health

`GET /health/deep`

Use only for bounded operator diagnostics when `DEEP_HEALTH_ENABLED=true`. It exposes dependency state and measured duration, but no credentials or connection strings.

**Token:** not required  
**Body:** none  
**Success:** `200 OK`

```json
{
  "healthy": true,
  "checks": {
    "postgresql": {
      "healthy": true,
      "schemaReady": true,
      "durationMs": 4.28
    }
  }
}
```

| Failure | Meaning |
|---|---|
| `404 ROUTE_NOT_FOUND` | Deep health is disabled; the feature is intentionally hidden. |
| `503 DEPENDENCY_HEALTH_CHECK_FAILED` | PostgreSQL or schema health failed; diagnostic values are returned in `error.details`. |

### 5.5 Authentication capabilities

`GET /api/v1/auth/capabilities`

Use before rendering registration, login, verification, or password UI. This is a safe public configuration endpoint; it does not expose roles, permissions, rate limits, key material, or internal policy implementation.

**Token:** not required  
**Optional header:** `If-None-Match: "<etag>"`  
**Body:** none  
**Success:** `200 OK`

```json
{
  "schema": "auth-capabilities",
  "registration": {
    "emailEnabled": true,
    "phoneEnabled": true
  },
  "login": {
    "passwordEnabled": true,
    "phoneOtpEnabled": true
  },
  "verification": {
    "emailRequired": true,
    "phoneRequired": true
  },
  "passwordPolicy": {
    "minimumLength": 12,
    "minimumCharacterClasses": 3
  },
  "supportedPlatforms": ["android", "ios", "web"]
}
```

The response includes `ETag` and is public-cacheable for 300 seconds. Send that value in `If-None-Match`; if unchanged, the server returns `304 Not Modified` with no JSON body. Reuse the cached representation.

### 5.6 JWKS

`GET /api/v1/auth/.well-known/jwks.json`

Use from gateways or resource services that validate RS256 access tokens locally. Cache keys according to operational policy and refresh when an unknown `kid` is observed. This endpoint never returns private keys.

**Token:** not required  
**Body:** none  
**Success:** `200 OK`

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "primary",
      "use": "sig",
      "alg": "RS256",
      "n": "<base64url-modulus>",
      "e": "AQAB"
    }
  ]
}
```

| Failure | Meaning |
|---|---|
| `404 RESOURCE_NOT_FOUND` | Service uses HS256 or no public JWKS keys are configured. Do not attempt to derive or request the signing secret. |
| `503 INFRASTRUCTURE_UNAVAILABLE` | Authentication runtime has not completed initialization. |

---

## 6. Registration endpoints

Public registration never accepts a role. The server assigns only the configured allowlisted self-registration role (normally `customer`). Supplying a `roles` property returns `422 REQUEST_VALIDATION_ERROR`.

### 6.1 Register with email and password

`POST /api/v1/auth/register/email`

Use to create a new email/password identity. When email verification is required, the response contains a verification challenge and no usable session. When verification is disabled, it may contain tokens immediately.

**Token:** not required  
**Optional headers:** `X-Client-ID`, `X-Platform`, `X-Device-ID`, `X-Device-Type`  
**Rate policy:** registration  
**Success:** `201 Created`

Request:

```json
{
  "email": "asha@example.com",
  "password": "S3cure!Account",
  "firstName": "Asha",
  "lastName": "Sen",
  "preferredName": "Asha",
  "preferredLocale": "en-IN",
  "timezone": "Asia/Kolkata",
  "termsVersion": "2026-01",
  "privacyVersion": "2026-01"
}
```

Required: `email`, `password`. Names are 1–100 characters when supplied; locale 2–16; timezone 3–64; consent version strings up to 32. Password is also evaluated against the stronger policy in §2.5.

Success `data` when verification is required:

```json
{
  "user": {"id": "b9c2e6c1-7485-413f-a232-b02f6d1950fa", "email": "asha@example.com", "emailVerified": false, "phoneCountryCode": null, "phoneNumberMasked": null, "phoneVerified": false, "status": "pending", "preferredLocale": "en-IN", "timezone": "Asia/Kolkata", "displayName": "Asha Sen", "profile": null},
  "verificationRequired": true,
  "challengeId": "ca4e81f0-bc8d-493c-a409-685527cb8f3d",
  "expiresAt": "2026-08-17T12:05:00Z",
  "developmentOtp": null,
  "tokens": null
}
```

When `verificationRequired=false`, `challengeId`, `expiresAt`, and `developmentOtp` are `null`; `tokens` contains the token-pair model from §4.2.

| Failure | Meaning |
|---|---|
| `409 AUTH_IDENTITY_ALREADY_EXISTS` | Normalized email is already registered; `details.field` is `email`. Route the user to login or recovery. |
| `422 REQUEST_VALIDATION_ERROR` | JSON/field contract failed, including unknown fields. |
| `422 VALIDATION_ERROR` | Email normalization or password policy failed. |
| `429 RATE_LIMIT_EXCEEDED` | Registration quota exceeded. |
| `503 INFRASTRUCTURE_UNAVAILABLE` | Required default role or infrastructure is unavailable. |

### 6.2 Request phone registration OTP

`POST /api/v1/auth/register/phone/request-otp`

Use as step 1 of phone registration. Persist `challengeId` only for the matching registration flow; it cannot be used for login or password reset.

**Token:** not required  
**Optional headers:** `X-Client-ID`, `X-Device-ID`  
**Rate policy:** OTP request  
**Success:** `200 OK`

```json
{
  "phoneCountryCode": "+91",
  "phoneNumber": "9876543210"
}
```

`phoneCountryCode` is 1–8 characters and `phoneNumber` is 6–32 before canonical phone validation. Success `data` is the OTP challenge from §4.3.

| Failure | Meaning |
|---|---|
| `409 AUTH_IDENTITY_ALREADY_EXISTS` | Country code and phone number are already registered. |
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | Field shape or normalized phone is invalid. |
| `429 RATE_LIMIT_EXCEEDED` | OTP request quota, resend cooldown, or resend window exceeded. |

### 6.3 Verify phone registration OTP

`POST /api/v1/auth/register/phone/verify-otp`

Use as step 2 of phone registration. It consumes the one-time challenge, creates the account with the server-controlled role, and creates the first session atomically.

**Token:** not required  
**Optional headers:** `X-Client-ID`, `X-Platform`, `X-Device-ID`, `X-Device-Type`  
**Rate policy:** OTP verify  
**Success:** `201 Created`

```json
{
  "challengeId": "ca4e81f0-bc8d-493c-a409-685527cb8f3d",
  "phoneCountryCode": "+91",
  "phoneNumber": "9876543210",
  "code": "482901",
  "password": "S3cure!Account",
  "firstName": "Asha",
  "lastName": "Sen",
  "preferredName": "Asha",
  "preferredLocale": "en-IN",
  "timezone": "Asia/Kolkata",
  "termsVersion": "2026-01",
  "privacyVersion": "2026-01"
}
```

Required: `challengeId`, phone fields, six-digit `code`. `password` and profile/consent fields are optional. When supplied, the password must satisfy §2.5. Success `data` is the token pair from §4.2.

| Failure | Meaning |
|---|---|
| `401 AUTH_OTP_EXPIRED`, `AUTH_OTP_INVALID`, `AUTH_OTP_ATTEMPTS_EXCEEDED`, `AUTH_OTP_ALREADY_USED` | Challenge cannot be accepted. Request a new registration OTP when appropriate. |
| `409 AUTH_IDENTITY_ALREADY_EXISTS` | Phone became registered before this transaction completed. |
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | Request, phone, or optional password failed validation. |
| `429 RATE_LIMIT_EXCEEDED` | OTP verification quota exceeded. |
| `503 INFRASTRUCTURE_UNAVAILABLE` | Default self-registration role or auth infrastructure is unavailable. |

---

## 7. Email verification endpoints

### 7.1 Request or resend email verification OTP

`POST /api/v1/auth/email-verification/request`

Use after email registration or when a pending user's verification challenge needs to be reissued. The route is public and purpose-bound.

**Token:** not required  
**Optional headers:** `X-Client-ID`, `X-Device-ID`  
**Rate policy:** OTP request  
**Success:** `200 OK`

```json
{"email": "asha@example.com"}
```

Success `data` is the OTP challenge from §4.3.

| Failure | Meaning |
|---|---|
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | Email shape or normalization is invalid. |
| `429 RATE_LIMIT_EXCEEDED` | OTP request quota/cooldown exceeded. |
| `503 INFRASTRUCTURE_UNAVAILABLE` | Auth/OTP infrastructure is unavailable. |

> Current implementation persists the challenge but has outbound notification delivery intentionally paused. Production integration must connect the notification gateway before relying on email delivery.

### 7.2 Verify email and issue session

`POST /api/v1/auth/email-verification/verify`

Use to consume a pending email-verification challenge, activate an eligible pending account, and create its session.

**Token:** not required  
**Optional headers:** `X-Client-ID`, `X-Platform`, `X-Device-ID`, `X-Device-Type`  
**Rate policy:** OTP verify  
**Success:** `200 OK`

```json
{
  "challengeId": "ca4e81f0-bc8d-493c-a409-685527cb8f3d",
  "email": "asha@example.com",
  "code": "482901"
}
```

Success `data` is the token pair from §4.2.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Verification code is invalid/expired, account is absent/already verified, or account policy blocks activation. The message remains client-safe. |
| `401 AUTH_OTP_*` | Purpose-bound OTP state is expired, invalid, blocked, or already consumed. |
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | UUID, email, or six-digit code format is invalid. |
| `429 RATE_LIMIT_EXCEEDED` | OTP verification quota exceeded. |

---

## 8. Login endpoints

### 8.1 Password login

`POST /api/v1/auth/login/password`

Use for password authentication by either email or phone. The `channel` determines which identity fields are required.

**Token:** not required  
**Optional headers:** `X-Client-ID`, `X-Platform`, `X-Device-ID`, `X-Device-Type`  
**Rate policy:** login  
**Success:** `200 OK`

Email request:

```json
{
  "channel": "email",
  "email": "asha@example.com",
  "password": "S3cure!Account"
}
```

Phone request:

```json
{
  "channel": "phone",
  "phoneCountryCode": "+91",
  "phoneNumber": "9876543210",
  "password": "S3cure!Account"
}
```

Success `data` is the token pair from §4.2.

| Failure | Meaning |
|---|---|
| `401 AUTH_INVALID_CREDENTIALS` | Identity/password is invalid or account policy is intentionally hidden behind the uniform credential response. Clear password input; do not reveal account existence. |
| `401 AUTH_ACCOUNT_LOCKED` / `AUTH_ACCOUNT_DISABLED` | Account lockout or account/verification policy blocks login where exposed by policy. |
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | Channel-specific identity fields are missing or invalid. |
| `429 RATE_LIMIT_EXCEEDED` | Login quota exceeded. |

After the configured failed-attempt threshold (default five), the account may be locked for the configured period (default 15 minutes).

### 8.2 Request phone login OTP

`POST /api/v1/auth/login/phone/request-otp`

Use as step 1 of passwordless phone login for an existing verified phone identity.

**Token:** not required  
**Optional headers:** `X-Client-ID`, `X-Device-ID`  
**Rate policy:** OTP request  
**Success:** `200 OK`

```json
{
  "phoneCountryCode": "+91",
  "phoneNumber": "9876543210"
}
```

Success `data` is the OTP challenge from §4.3. The service is designed to avoid unsafe account-detail disclosure; client copy should remain generic.

| Failure | Meaning |
|---|---|
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | Phone input is invalid. |
| `429 RATE_LIMIT_EXCEEDED` | OTP request quota/cooldown exceeded. |
| `503 INFRASTRUCTURE_UNAVAILABLE` | OTP/auth infrastructure is unavailable. |

> Current implementation persists the challenge but has outbound SMS delivery intentionally paused. Connect the notification gateway for production delivery.

### 8.3 Verify phone login OTP

`POST /api/v1/auth/login/phone/verify-otp`

Use as step 2 of phone OTP login. The challenge is consumed and a new session is created.

**Token:** not required  
**Optional headers:** `X-Client-ID`, `X-Platform`, `X-Device-ID`, `X-Device-Type`  
**Rate policy:** OTP verify  
**Success:** `200 OK`

```json
{
  "challengeId": "ca4e81f0-bc8d-493c-a409-685527cb8f3d",
  "phoneCountryCode": "+91",
  "phoneNumber": "9876543210",
  "code": "482901"
}
```

Success `data` is the token pair from §4.2.

| Failure | Meaning |
|---|---|
| `401 AUTH_INVALID_CREDENTIALS` | OTP, phone identity, or account eligibility is invalid; response is deliberately uniform. |
| `401 AUTH_OTP_*` | OTP is expired, invalid, blocked, or already used. |
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | Request format is invalid. |
| `429 RATE_LIMIT_EXCEEDED` | OTP verification quota exceeded. |

---

## 9. Token and logout endpoints

### 9.1 Rotate refresh token

`POST /api/v1/auth/token/refresh`

Use when the access token is near expiry or has expired while the refresh token remains valid. The operation rotates the refresh token; a successful response invalidates the submitted token.

**Access token:** not required  
**Credential:** refresh token in body  
**Optional headers:** `X-Client-ID`, `X-Device-ID`  
**Rate policy:** refresh  
**Success:** `200 OK`

```json
{"refreshToken": "<current-refresh-jwt>"}
```

The token is 32–8192 characters at the transport boundary. Success `data` is the new token pair from §4.2.

Client algorithm:

1. Serialize refresh attempts per local session; do not refresh concurrently with the same token.
2. On success, atomically replace both tokens.
3. Retry the original API request once with the new access token.
4. On any terminal `401`, clear local tokens and return to login.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Refresh token is malformed, wrong type, has invalid claims, belongs to a missing session/user, or fails an optional supplied device assertion. |
| `401 AUTH_SESSION_REVOKED` | Persisted session is revoked or expired. |
| `401 AUTH_REFRESH_TOKEN_REUSE` | Old/mismatched token in a family was reused; the family is revoked. Clear credentials immediately. |
| `401 AUTH_ACCOUNT_*` | Account policy no longer permits authentication. |
| `422 REQUEST_VALIDATION_ERROR` | Body is absent or token length is invalid. |
| `429 RATE_LIMIT_EXCEEDED` | Refresh quota exceeded. |

### 9.2 Logout by refresh token

`POST /api/v1/auth/logout`

Use when the client has a refresh token and wants to revoke its associated session, including when the access token has expired. The response is intentionally idempotent for an already-revoked/missing persisted session after a structurally valid refresh token is decoded.

**Access token:** not required  
**Credential:** refresh token in body  
**Optional headers:** `X-Client-ID`, `X-Device-ID`  
**Rate policy:** refresh logout  
**Success:** `200 OK`

```json
{"refreshToken": "<refresh-jwt>"}
```

Success `data`:

```json
{"message": "The session has been logged out."}
```

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Refresh token cannot be decoded as a valid refresh credential. |
| `422 REQUEST_VALIDATION_ERROR` | Request body/token length is invalid. |
| `429 RATE_LIMIT_EXCEEDED` | Logout quota exceeded. |

Regardless of response outcome, the client should delete its local token pair when the user explicitly signs out.

### 9.3 Logout other devices

`POST /api/v1/auth/logout/others`

Use from a security/session-management screen to revoke every current-user session except the bearer session making this call.

**Token:** bearer access token required  
**Permission:** none beyond authenticated self-service  
**Rate policy:** sensitive  
**Body:** none  
**Success:** `200 OK`

```json
{"message": "All other sessions have been logged out."}
```

Errors: `401 AUTHENTICATION_REQUIRED` for invalid/revoked bearer session, `429 RATE_LIMIT_EXCEEDED`, and common infrastructure errors. The current token pair remains valid.

### 9.4 Logout all devices

`POST /api/v1/auth/logout/all`

Use when the user wants to invalidate all sessions, including the one making the request. After success, clear local credentials before any further call.

**Token:** bearer access token required  
**Permission:** none beyond authenticated self-service  
**Rate policy:** sensitive  
**Body:** none  
**Success:** `200 OK`

```json
{"message": "All sessions have been logged out."}
```

Errors: `401 AUTHENTICATION_REQUIRED`, `429 RATE_LIMIT_EXCEEDED`, and common infrastructure errors.

---

## 10. Session management endpoints

### 10.1 List active sessions

`GET /api/v1/auth/sessions`

Use for a user's “devices and sessions” screen. Only active, unexpired sessions owned by the authenticated user are returned. `current=true` identifies the caller's bearer session.

**Token:** bearer access token required  
**Permission:** none beyond authenticated self-service  
**Rate policy:** standard  
**Body:** none  
**Success:** `200 OK`

```json
{
  "sessions": [
    {
      "id": "9d3bb1b9-0581-4e89-a189-3df237e3ebbb",
      "deviceId": "web-installation-8342",
      "deviceType": "browser",
      "ipAddress": "203.0.113.42",
      "userAgent": "Mozilla/5.0 ...",
      "createdAt": "2026-08-17T11:00:00Z",
      "lastSeenAt": "2026-08-17T12:00:00Z",
      "expiresAt": "2026-09-16T11:00:00Z",
      "current": true
    }
  ]
}
```

Session metadata fields may be `null`. Treat IP and user-agent strings as informational, not as proof of device identity.

Errors: `401 AUTHENTICATION_REQUIRED`, `429 RATE_LIMIT_EXCEEDED`, and common infrastructure errors.

### 10.2 Revoke selected session

`DELETE /api/v1/auth/sessions/{sessionId}`

Use to revoke one session selected from the active-session list. Ownership is checked server-side; a foreign session ID is indistinguishable from a missing one.

**Token:** bearer access token required  
**Permission:** none beyond authenticated self-service  
**Rate policy:** sensitive  
**Path:** `sessionId` — UUID  
**Body:** none  
**Success:** `200 OK`

```json
{"message": "The session has been revoked."}
```

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Bearer token/session is invalid. |
| `404 RESOURCE_NOT_FOUND` | Session does not exist or is not owned by the caller. |
| `422 REQUEST_VALIDATION_ERROR` | `sessionId` is not a UUID. |
| `429 RATE_LIMIT_EXCEEDED` | Sensitive-operation quota exceeded. |

The implementation also allows revocation of the current session. If `sessionId` is the current session, clear local tokens after success.

---

## 11. Password management endpoints

### 11.1 Request password reset OTP

`POST /api/v1/auth/password/forgot`

Use as step 1 of account recovery. The endpoint returns a generic OTP-challenge contract and should not be used to determine whether an account exists.

**Token:** not required  
**Optional headers:** `X-Client-ID`, `X-Device-ID`  
**Rate policy:** password reset  
**Success:** `200 OK`

Email request:

```json
{"channel": "email", "email": "asha@example.com"}
```

SMS request:

```json
{"channel": "sms", "phoneCountryCode": "+91", "phoneNumber": "9876543210"}
```

Success `data` is the OTP challenge from §4.3. Use `channel=email` with `email`; use `channel=sms` with both phone fields.

| Failure | Meaning |
|---|---|
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | Channel/destination is missing or invalid. |
| `429 RATE_LIMIT_EXCEEDED` | Password-recovery quota or OTP resend policy exceeded. |

> Email/SMS notification calls are currently paused in the implementation. Connect the notification gateway before production recovery depends on external delivery.

### 11.2 Verify password reset OTP

`POST /api/v1/auth/password/reset/verify-otp`

Use as step 2 of recovery. It consumes the OTP and returns a short-lived, signed, one-time reset proof. Do not use that proof as an API bearer token.

**Token:** not required  
**Optional headers:** `X-Client-ID`, `X-Device-ID`  
**Rate policy:** OTP verify  
**Success:** `200 OK`

```json
{
  "channel": "email",
  "email": "asha@example.com",
  "challengeId": "ca4e81f0-bc8d-493c-a409-685527cb8f3d",
  "code": "482901"
}
```

For SMS, replace `email` with `phoneCountryCode` and `phoneNumber` and set `channel` to `sms`.

Success `data`:

```json
{
  "resetToken": "<password-reset-jwt>",
  "expiresAt": "2026-08-17T12:10:00Z"
}
```

The default reset-proof lifetime is 10 minutes.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` / `AUTH_OTP_*` | Code is invalid/expired, challenge does not match the identity/purpose, account is absent, or account policy blocks recovery. |
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | Identity, UUID, channel, or code shape is invalid. |
| `429 RATE_LIMIT_EXCEEDED` | Verification quota exceeded. |

### 11.3 Reset password with proof

`POST /api/v1/auth/password/reset`

Use as step 3 of recovery. It validates the reset proof, enforces password policy/history, revokes older sessions, marks the proof consumed, and creates one replacement session.

**Access token:** not required  
**Credential:** reset proof in body  
**Optional headers:** `X-Client-ID`, `X-Platform`, `X-Device-ID`, `X-Device-Type`  
**Success:** `200 OK`

```json
{
  "resetToken": "<password-reset-jwt>",
  "newPassword": "N3w!SecureAccount"
}
```

Success `data` is the token pair from §4.2.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Proof is invalid, expired, already redeemed, wrong type, or inconsistent with the consumed challenge. |
| `401 AUTH_ACCOUNT_*` | Account no longer permits login. |
| `422 REQUEST_VALIDATION_ERROR` | Proof/password transport shape is invalid. |
| `422 VALIDATION_ERROR` | New password fails strength, identity-fragment, or history policy. |

### 11.4 Change existing password

`PUT /api/v1/auth/password`

Use for an authenticated account that already has a password. This verifies the current password, rejects recent-password reuse, revokes every existing session, and creates one replacement session.

**Token:** bearer access token required  
**Optional session headers:** `X-Client-ID`, `X-Platform`, `X-Device-ID`, `X-Device-Type`  
**Rate policy:** sensitive  
**Success:** `200 OK`

```json
{
  "currentPassword": "S3cure!Account",
  "newPassword": "N3w!SecureAccount"
}
```

Success `data` is the new token pair from §4.2. Replace local credentials immediately.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Bearer session is invalid or current password is incorrect. |
| `404 RESOURCE_NOT_FOUND` | Authenticated user record no longer exists. |
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | Body or new-password policy failed. |
| `429 RATE_LIMIT_EXCEEDED` | Sensitive-operation quota exceeded. |

### 11.5 Set initial password

`POST /api/v1/auth/password`

Use only for an authenticated OTP-only account without a password hash. It establishes the initial password, revokes previous sessions, and creates one replacement session.

**Token:** bearer access token required  
**Optional session headers:** `X-Client-ID`, `X-Platform`, `X-Device-ID`, `X-Device-Type`  
**Rate policy:** sensitive  
**Success:** `200 OK`

```json
{"newPassword": "N3w!SecureAccount"}
```

Success `data` is the new token pair from §4.2.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Bearer session is invalid. |
| `404 RESOURCE_NOT_FOUND` | User no longer exists. |
| `409 RESOURCE_CONFLICT` | Password is already configured; use `PUT /auth/password`. |
| `422 REQUEST_VALIDATION_ERROR` / `VALIDATION_ERROR` | Body or password policy failed. |
| `429 RATE_LIMIT_EXCEEDED` | Sensitive-operation quota exceeded. |

---


## 12. Current-user endpoints

### 12.1 Get current authorization

`GET /api/v1/auth/users/me/authorization`

Use to refresh client-side feature visibility after login, role changes, or authorization-sensitive navigation. The result reflects current active global authorization loaded from PostgreSQL; it is not copied from client headers.

**Token:** bearer access token required  
**Permission:** none beyond authenticated self-service  
**Rate policy:** standard  
**Body:** none  
**Success:** `200 OK`

```json
{
  "roles": ["customer"],
  "permissions": ["orders.create", "profile.read", "profile.update"]
}
```

Arrays are sorted and may be empty. Scope-specific assignments are not expanded into a separate response model here.

Errors: `401 AUTHENTICATION_REQUIRED`, `429 RATE_LIMIT_EXCEEDED`, and common infrastructure errors.

### 12.2 Get current user

`GET /api/v1/users/me`

Use to populate the signed-in profile and account-preference view. It deliberately excludes roles and permissions; use §12.1 for authorization.

**Token:** bearer access token required  
**Permission:** none beyond authenticated self-service  
**Rate policy:** standard  
**Body:** none  
**Success:** `200 OK`

Success `data` is the authenticated-user model from §4.1.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Access token/session/account is invalid. |
| `404 RESOURCE_NOT_FOUND` | User record no longer exists. |
| `429 RATE_LIMIT_EXCEEDED` | Standard quota exceeded. |

### 12.3 Update current user

`PATCH /api/v1/users/me`

Use to update preferences and optional profile data. Login identifiers (email and phone), status, roles, and permissions are not editable here.

**Token:** bearer access token required  
**Permission:** none beyond authenticated self-service  
**Rate policy:** sensitive  
**Success:** `200 OK`

```json
{
  "preferredLocale": "bn-IN",
  "timezone": "Asia/Kolkata",
  "firstName": "Asha",
  "lastName": "Sen",
  "preferredName": "Asha",
  "avatarFileId": "119432a7-48a1-4cbe-975b-7787f2aa811c"
}
```

All fields are optional. Names are 1–100 characters when non-null; locale 2–16; timezone 3–64. Explicit `null` clears profile name fields or detaches `avatarFileId`. For locale/timezone, `null` is ignored by the current service update logic. An empty object is accepted as a no-op.

`avatarFileId` must reference an available public image owned by the current user and created for scope `identity.user_profile.avatar`.

Success `data` is the updated authenticated-user model from §4.1.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Bearer session is invalid. |
| `404 RESOURCE_NOT_FOUND` | User no longer exists. |
| `422 REQUEST_VALIDATION_ERROR` | Field type/length or unknown property is invalid. |
| `422 VALIDATION_ERROR` | Avatar is absent, unavailable, non-public, wrong scope, or not owned by the caller. |
| `429 RATE_LIMIT_EXCEEDED` | Sensitive-operation quota exceeded. |

---

## 13. Administrative user endpoints

Administrative authorization is permission-based. An “admin” role name alone does not grant an operation unless its effective permissions include the code shown below.

### 13.1 List users

`GET /api/v1/admin/users`

Use for a bounded administrative user directory. Results are ordered by newest creation time and then UUID for deterministic pagination.

**Token:** bearer access token required  
**Permission:** `identity.users.read`  
**Rate policy:** admin read  
**Body:** none  
**Success:** `200 OK`

Query parameters:

| Parameter | Type/default | Rules | Behavior |
|---|---|---|---|
| `limit` | integer, `20` | 1–100 | Maximum users in this page. |
| `offset` | integer, `0` | 0–100000 | Number of matching rows to skip. |
| `search` | string, optional | 2–320 chars | Case-insensitive partial match against normalized email, phone number, first/last/preferred name, or full first+last name. |
| `status` | enum, optional | `pending`, `active`, `locked`, `suspended`, `closed` | Exact account-status filter. |

Example:

```http
GET /api/v1/admin/users?limit=20&offset=0&search=asha&status=active
Authorization: Bearer <access-token>
```

Success `data`:

```json
{
  "users": [
    {
      "id": "b9c2e6c1-7485-413f-a232-b02f6d1950fa",
      "email": "asha@example.com",
      "emailVerified": true,
      "phoneCountryCode": "+91",
      "phoneNumberMasked": "******3210",
      "phoneVerified": true,
      "status": "active",
      "preferredLocale": "en-IN",
      "timezone": "Asia/Kolkata",
      "displayName": "Asha Sen",
      "profile": null,
      "roles": ["customer"],
      "permissions": ["profile.read", "profile.update"]
    }
  ]
}
```

Read `meta.pagination` as documented in §2.2. An empty page is successful.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Bearer session is invalid. |
| `403 PERMISSION_DENIED` | `identity.users.read` is missing; `details.missingPermissions` identifies the requirement. |
| `422 REQUEST_VALIDATION_ERROR` | Query value is invalid. |
| `429 RATE_LIMIT_EXCEEDED` | Admin-read quota exceeded. |

### 13.2 Get user

`GET /api/v1/admin/users/{userId}`

Use to load one identity together with current active global roles and permissions.

**Token:** bearer access token required  
**Permission:** `identity.users.read`  
**Rate policy:** admin read  
**Path:** `userId` — UUID  
**Body:** none  
**Success:** `200 OK`

Success `data` is one user object in the shape shown in §13.1.

Errors: `401 AUTHENTICATION_REQUIRED`, `403 PERMISSION_DENIED`, `404 RESOURCE_NOT_FOUND`, `422 REQUEST_VALIDATION_ERROR` for a non-UUID path, and `429 RATE_LIMIT_EXCEEDED`.

### 13.3 Update user status

`PATCH /api/v1/admin/users/{userId}/status`

Use to activate, lock, suspend, close, or move an account to pending state. The reason is retained in the security audit log. By default, moving to any non-active status revokes all target-user sessions.

**Token:** bearer access token required  
**Permission:** `identity.users.manage`  
**Rate policy:** admin write  
**Path:** `userId` — UUID  
**Success:** `200 OK`

```json
{
  "status": "suspended",
  "reason": "Confirmed policy violation ticket SEC-4821",
  "revokeSessions": true
}
```

`reason` is required and 3–255 characters. `revokeSessions` defaults to `true`. Setting `active` clears `lockedUntil` and failed-login count. Setting `closed` records account closure; moving away from `closed` clears the closure marker.

Success `data` is the updated admin user model.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Bearer session is invalid. |
| `403 PERMISSION_DENIED` | `identity.users.manage` is missing. |
| `404 RESOURCE_NOT_FOUND` | Target user does not exist. |
| `409 RESOURCE_CONFLICT` | Administrator attempted to set their own account to a non-active status. Use a separate break-glass/peer-admin process. |
| `422 REQUEST_VALIDATION_ERROR` | UUID, status, reason, or body is invalid. |
| `429 RATE_LIMIT_EXCEEDED` | Admin-write quota exceeded. |

### 13.4 Administratively logout user from all devices

`POST /api/v1/admin/users/{userId}/logout-all`

Use during account compromise response, support-led sign-out, or access remediation. It revokes every active session for the target user and writes an actor/target/reason security audit event.

**Token:** bearer access token required  
**Permission:** `identity.users.manage`  
**Rate policy:** admin write  
**Path:** `userId` — UUID  
**Success:** `200 OK`

```json
{"reason": "User reported lost device"}
```

The body is required by FastAPI, but `reason` itself defaults to `administrative_logout_all` when an empty JSON object is supplied. Prefer an explicit incident/support reason.

Success `data`:

```json
{"message": "All user sessions have been revoked."}
```

Errors: `401 AUTHENTICATION_REQUIRED`, `403 PERMISSION_DENIED`, `404 RESOURCE_NOT_FOUND`, `422 REQUEST_VALIDATION_ERROR`, and `429 RATE_LIMIT_EXCEEDED`.

---

## 14. Administrative role endpoints

Only active (non-deleted) roles are returned. Delete is a soft delete. System roles may be renamed/described, but their code cannot be changed and they cannot be deleted.

### 14.1 List roles

`GET /api/v1/admin/roles`

**Token:** bearer required  
**Permission:** `identity.roles.read`  
**Rate policy:** admin read  
**Body:** none  
**Success:** `200 OK`

```json
{"roles": [{"id": "264920dd-2af4-4b1c-9865-a78a0e47b97a", "code": "support_agent", "name": "Support Agent", "description": "Customer support access", "isSystem": false, "createdAt": "2026-08-17T11:00:00Z", "updatedAt": "2026-08-17T11:00:00Z"}]}
```

Errors: `401 AUTHENTICATION_REQUIRED`, `403 PERMISSION_DENIED`, `429 RATE_LIMIT_EXCEEDED`, and common infrastructure errors.

### 14.2 Create role

`POST /api/v1/admin/roles`

Use to create a custom role before assigning permissions and users.

**Token:** bearer required  
**Permission:** `identity.roles.manage`  
**Rate policy:** admin write  
**Success:** `201 Created`

```json
{
  "code": "support_agent",
  "name": "Support Agent",
  "description": "Customer support access"
}
```

`code` must match `^[a-z][a-z0-9_.-]{1,63}$`; `name` is 2–128 characters; description is optional up to 2000. Success `data` is the role model from §4.4 with `isSystem=false`.

Errors: `401 AUTHENTICATION_REQUIRED`, `403 PERMISSION_DENIED`, `409 RESOURCE_CONFLICT` for duplicate active code, `422 REQUEST_VALIDATION_ERROR`, and `429 RATE_LIMIT_EXCEEDED`.

### 14.3 Get role

`GET /api/v1/admin/roles/{roleId}`

**Token:** bearer required  
**Permission:** `identity.roles.read`  
**Rate policy:** admin read  
**Path:** `roleId` — UUID  
**Success:** `200 OK`; `data` is the role model from §4.4.

Errors: `401`, `403`, `404 RESOURCE_NOT_FOUND` for absent/deleted role, `422` for invalid UUID, and `429`.

### 14.4 Update role

`PATCH /api/v1/admin/roles/{roleId}`

Use for partial changes. At least one field must be supplied. Omitted fields are unchanged; `description:null` clears the description.

**Token:** bearer required  
**Permission:** `identity.roles.manage`  
**Rate policy:** admin write  
**Path:** `roleId` — UUID  
**Success:** `200 OK`

```json
{
  "name": "Senior Support Agent",
  "description": "Expanded customer support access"
}
```

Errors: `401`, `403`, `404`, `409 RESOURCE_CONFLICT` for duplicate code or attempted system-role code change, `422` for empty/invalid update, and `429`.

### 14.5 Delete role

`DELETE /api/v1/admin/roles/{roleId}`

Use to soft-delete a custom role. Do not use it to remove a role from one user; delete that assignment through §16.4.

**Token:** bearer required  
**Permission:** `identity.roles.manage`  
**Rate policy:** admin write  
**Path:** `roleId` — UUID  
**Body:** none  
**Success:** `200 OK`

```json
{"message": "The role has been deleted."}
```

Errors: `401`, `403`, `404`, `409 RESOURCE_CONFLICT` for a system role, `422` for invalid UUID, and `429`.

---

## 15. Permission and role-policy endpoints

Permissions are fine-grained master records. Role policy is replaced as a complete set, which avoids partial, order-dependent permission drift.

### 15.1 List permissions

`GET /api/v1/admin/permissions`

**Token:** bearer required  
**Permission:** `identity.permissions.read`  
**Rate policy:** admin read  
**Body:** none  
**Success:** `200 OK`

```json
{"permissions": [{"id": "f1081e64-5c33-49bd-b8c2-2cffbc49677a", "code": "identity.users.read", "resource": "identity.users", "action": "read", "description": "Read identity users", "createdAt": "2026-08-17T11:00:00Z", "updatedAt": "2026-08-17T11:00:00Z"}]}
```

Errors: `401 AUTHENTICATION_REQUIRED`, `403 PERMISSION_DENIED`, `429 RATE_LIMIT_EXCEEDED`, and common infrastructure errors.

### 15.2 Create permission

`POST /api/v1/admin/permissions`

Use to define one atomic authorization capability.

**Token:** bearer required  
**Permission:** `identity.permissions.manage`  
**Rate policy:** admin write  
**Success:** `201 Created`

```json
{
  "code": "identity.users.read",
  "resource": "identity.users",
  "action": "read",
  "description": "Read identity users"
}
```

Rules:

- `code`: `^[a-z][a-z0-9_.:-]{1,127}$`
- `resource`: `^[a-z][a-z0-9_.-]{1,63}$`
- `action`: `^[a-z][a-z0-9_-]{1,63}$`
- `description`: optional, up to 2000

Success `data` is the permission model from §4.4.

Errors: `401`, `403`, `409 PERMISSION_CODE_ALREADY_EXISTS` (including concurrent uniqueness races), `422`, and `429`.

### 15.3 Get permission

`GET /api/v1/admin/permissions/{permissionId}`

**Token:** bearer required  
**Permission:** `identity.permissions.read`  
**Rate policy:** admin read  
**Path:** `permissionId` — UUID  
**Success:** `200 OK`; `data` is the permission model.

Errors: `401`, `403`, `404 RESOURCE_NOT_FOUND`, `422`, and `429`.

### 15.4 Update permission

`PATCH /api/v1/admin/permissions/{permissionId}`

Use for partial changes. At least one field is required. `code`, `resource`, and `action` cannot be explicitly `null`; `description:null` clears the description.

**Token:** bearer required  
**Permission:** `identity.permissions.manage`  
**Rate policy:** admin write  
**Success:** `200 OK`

```json
{"description": "Read identity users and their active authorization"}
```

Errors: `401`, `403`, `404`, `409 PERMISSION_CODE_ALREADY_EXISTS`, `422` for empty/invalid/null-required update, and `429`.

### 15.5 Delete permission

`DELETE /api/v1/admin/permissions/{permissionId}`

Use to soft-delete a permission master. Existing audit history is retained.

**Token:** bearer required  
**Permission:** `identity.permissions.manage`  
**Rate policy:** admin write  
**Success:** `200 OK`

```json
{"message": "The permission has been deleted."}
```

Errors: `401`, `403`, `404`, `422`, and `429`.

### 15.6 Get role permissions

`GET /api/v1/admin/roles/{roleId}/permissions`

Use to load the complete active permission set for a role before editing policy.

**Token:** bearer required  
**Permission:** `identity.permissions.read`  
**Rate policy:** admin read  
**Path:** `roleId` — UUID  
**Success:** `200 OK`

```json
{
  "roleId": "264920dd-2af4-4b1c-9865-a78a0e47b97a",
  "permissions": [
    {
      "id": "f1081e64-5c33-49bd-b8c2-2cffbc49677a",
      "code": "identity.users.read",
      "resource": "identity.users",
      "action": "read",
      "description": "Read identity users",
      "createdAt": "2026-08-17T11:00:00Z",
      "updatedAt": "2026-08-17T11:00:00Z"
    }
  ]
}
```

Errors: `401`, `403`, `404 RESOURCE_NOT_FOUND` for role, `422`, and `429`.

### 15.7 Replace role permissions

`PUT /api/v1/admin/roles/{roleId}/permissions`

Use to atomically make the role's policy exactly equal to `permissionIds`. This is replacement, not additive merge. An empty array removes all explicit permissions from the role.

**Token:** bearer required  
**Permission:** `identity.permissions.manage`  
**Rate policy:** admin write  
**Path:** `roleId` — UUID  
**Success:** `200 OK`

```json
{
  "permissionIds": [
    "f1081e64-5c33-49bd-b8c2-2cffbc49677a",
    "bb7cb11a-f247-4650-bf86-64e0069347f7"
  ]
}
```

`permissionIds` defaults to `[]`, allows up to 1000 IDs, and rejects duplicates. Every ID must identify an active permission. Success `data` is the role-permissions object from §15.6, ordered by permission code.

| Failure | Meaning |
|---|---|
| `401 AUTHENTICATION_REQUIRED` | Invalid bearer session. |
| `403 PERMISSION_DENIED` | `identity.permissions.manage` is missing. |
| `404 RESOURCE_NOT_FOUND` | Role is absent/deleted. |
| `422 REQUEST_VALIDATION_ERROR` | IDs are invalid/duplicated or list exceeds 1000. |
| `422 VALIDATION_ERROR` | One or more IDs are absent/deleted; `details.missingPermissionIds` lists them. |
| `429 RATE_LIMIT_EXCEEDED` | Admin-write quota exceeded. |

---

## 16. User-role assignment endpoints

A role assignment is either global (`scopeType` and `scopeId` both `null`) or scoped (both supplied). Validity windows are optional. Effective global authorization includes only active, currently valid assignments according to the authorization query.

### 16.1 List user role assignments

`GET /api/v1/admin/users/{userId}/roles`

Use to inspect all explicit global/scoped assignments for one user, including inactive and future/expired records returned by the assignment repository.

**Token:** bearer required  
**Permission:** `identity.user_roles.read`  
**Rate policy:** admin read  
**Path:** `userId` — UUID  
**Success:** `200 OK`

```json
{"assignments": [{"id": "1e58f27b-256d-46a1-84d2-66b708ba7c6f", "userId": "b9c2e6c1-7485-413f-a232-b02f6d1950fa", "roleId": "264920dd-2af4-4b1c-9865-a78a0e47b97a", "roleCode": "support_agent", "roleName": "Support Agent", "scopeType": null, "scopeId": null, "validFrom": null, "validUntil": null, "isActive": true, "createdAt": "2026-08-17T11:00:00Z", "updatedAt": "2026-08-17T11:00:00Z"}]}
```

Errors: `401`, `403`, `404 RESOURCE_NOT_FOUND` for target user, `422`, and `429`.

### 16.2 Assign role to user

`POST /api/v1/admin/users/{userId}/roles`

Use to create one global or scoped assignment for an existing user and active role.

**Token:** bearer required  
**Permission:** `identity.user_roles.manage`  
**Rate policy:** admin write  
**Success:** `201 Created`

```json
{
  "roleId": "264920dd-2af4-4b1c-9865-a78a0e47b97a",
  "scopeType": "tenant",
  "scopeId": "54a18d98-88ef-442b-a570-f97fbc487e04",
  "validFrom": "2026-08-17T00:00:00Z",
  "validUntil": "2027-08-17T00:00:00Z",
  "isActive": true
}
```

Only `roleId` is required. `scopeType` is 2–32 characters and must be supplied with `scopeId`; omit both for global access. When both dates exist, `validUntil` must be later than `validFrom`. Success `data` is the assignment model from §4.4.

Errors: `401`, `403`, `404 RESOURCE_NOT_FOUND` for user/role, `409 RESOURCE_CONFLICT` for a database uniqueness conflict, `422` for invalid scope/window, and `429`.

### 16.3 Update user-role assignment

`PATCH /api/v1/admin/users/{userId}/roles/{userRoleId}`

Use to change scope, validity, or active state. The assignment must belong to the `{userId}` in the route.

**Token:** bearer required  
**Permission:** `identity.user_roles.manage`  
**Rate policy:** admin write  
**Success:** `200 OK`

```json
{
  "validUntil": "2027-12-31T23:59:59Z",
  "isActive": true
}
```

At least one field is required. If either scope field is part of the update, the resulting submitted scope pair must be complete. The service also validates the final date window against existing values.

Errors: `401`, `403`, `404 RESOURCE_NOT_FOUND` for missing/foreign assignment, `422 REQUEST_VALIDATION_ERROR` or `VALIDATION_ERROR` for empty/scope/window errors, and `429`.

### 16.4 Remove user-role assignment

`DELETE /api/v1/admin/users/{userId}/roles/{userRoleId}`

Use to hard-delete one explicit assignment. This does not delete the role or user.

**Token:** bearer required  
**Permission:** `identity.user_roles.manage`  
**Rate policy:** admin write  
**Body:** none  
**Success:** `200 OK`

```json
{"message": "The user-role assignment has been removed."}
```

Errors: `401`, `403`, `404 RESOURCE_NOT_FOUND` for missing/foreign assignment, `422` for invalid UUID, and `429`.

---

## 17. Client workflow guidance

### 17.1 Email registration

1. `GET /auth/capabilities`; verify email registration is enabled.
2. `POST /auth/register/email`.
3. If `verificationRequired=true`, retain the returned `challengeId` and show the verification screen.
4. `POST /auth/email-verification/verify` with email, challenge, and code.
5. Store the returned token pair and load `/users/me` plus `/auth/users/me/authorization`.

### 17.2 Phone registration or OTP login

1. Call the purpose-specific `request-otp` endpoint.
2. Respect `retryAfterSeconds`; do not enable resend before it expires.
3. Submit the returned `challengeId` only to its matching `verify-otp` endpoint.
4. On success, replace/store the returned token pair.

Challenges are purpose-bound. A registration challenge cannot authenticate login, verify email, or reset a password.

### 17.3 Access-token refresh

Use a single-flight refresh mechanism per client session. A common browser/mobile algorithm is:

```text
API request -> 401 caused by expired access token
  -> if no refresh is running, POST /auth/token/refresh once
  -> atomically store returned pair
  -> replay queued request once
  -> if refresh returns 401, clear credentials and require login
```

Do not refresh in response to `403`; permissions will not appear merely by rotating a token because authorization is loaded from current database state on each protected request.

### 17.4 Administrative policy change

Recommended sequence:

1. Create or identify permission masters.
2. Create or identify the role.
3. Read the role's current permission set.
4. Compute the desired complete set client-side.
5. Replace it atomically with `PUT /admin/roles/{roleId}/permissions`.
6. Assign the role through `/admin/users/{userId}/roles`.
7. Re-read current user/role state for confirmation.

Because protected requests resolve current database authorization, permission and role changes take effect without requiring a new access token, subject to transaction completion and any surrounding service cache policy.

---

## 18. Reliability, security, and compatibility rules

### 18.1 Retry safety

| Operation type | Automatic retry guidance |
|---|---|
| GET/read | Retry transient `503/504` with bounded exponential backoff and jitter. |
| OTP request | Do not retry blindly; honor cooldown and inspect whether a challenge was returned. |
| Login/verify | Do not automatically repeat credential or OTP attempts; they affect lock/attempt counters. |
| Refresh | Serialize and retry only when client can prove the prior request did not complete; refresh tokens rotate. |
| Logout/revocation | Safe to reconcile by reloading sessions, but avoid uncontrolled repeated writes. |
| POST create | Do not retry after an ambiguous timeout without a reconciliation query; the API has no idempotency-key contract. |
| PUT/PATCH admin | Reload current state before retrying after conflict or ambiguous failure. |

### 18.2 Sensitive-data handling

- Redact `password`, `currentPassword`, `newPassword`, `code`, `accessToken`, `refreshToken`, and `resetToken` from logs, tracing, analytics, APM breadcrumbs, and support screenshots.
- Do not expose raw phone numbers returned from internal stores. API projections intentionally mask them.
- Do not cache token, session, current-user, or admin responses in shared caches.
- Restrict JWKS caching to public key material only.
- Treat request/correlation IDs as diagnostic identifiers, not authorization secrets.

### 18.3 Backward compatibility

Within `/api/v1`, compatible changes may add optional response properties or new error-detail fields. Clients must ignore unknown response fields. Renaming/removing fields, changing required inputs, narrowing enums, changing endpoint meaning, or changing token semantics requires versioning and a migration/deprecation plan.

Request bodies remain strict: clients must not proactively send newly guessed fields because unknown inputs are rejected.

### 18.4 Consumer contract checklist

Before releasing a client integration, verify:

- every protected request uses `Authorization: Bearer <accessToken>`;
- refresh and logout use `refreshToken` in JSON, not the authorization header;
- roles/permissions are never sent as trusted headers;
- camelCase is used in JSON and query/path parameter names;
- token rotation atomically replaces both tokens;
- OTP challenge IDs stay bound to the correct purpose and identity;
- `401`, `403`, `409`, `422`, `429`, and `503` are handled distinctly;
- `Retry-After`, request ID, and correlation ID are captured;
- admin screens enforce permission-based visibility but still rely on server authorization;
- secrets and OTPs are redacted from every telemetry path;
- all calls use HTTPS outside local development.

---

## 19. Documentation maintenance

When changing this API:

1. Update route declaration, Pydantic schema, service validation, and OpenAPI error responses together.
2. Add or update contract tests in `tests/contract/test_auth_openapi.py`.
3. Verify every bearer route has declarative security and the intended risk-based rate policy.
4. Regenerate `/openapi.json` in a test configuration and compare methods, paths, schemas, security, and response status codes.
5. Update this file's endpoint catalogue, detailed contract, errors, and workflow guidance.
6. Document any client migration, rollout order, deprecation period, and rollback behavior.

The current release intentionally exposes no MFA endpoints and no machine-to-machine API-client token flow. Do not infer those capabilities from enum names or future-facing internal code; only documented routes are supported.
