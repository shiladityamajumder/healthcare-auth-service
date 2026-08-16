# Authentication API

Routes are below the configured API version, normally `/api/v1`. Responses use `success`, `data`, `error`, and request/correlation metadata. Common errors: 400/422 invalid input, 401 missing credentials, 403 insufficient permission, 404 missing resource, 409 conflict, 429 rate limit, 500/503 dependency failure.

## Public routes

| Method | Path | Authorization | Use |
|---|---|---|---|
| POST | `/auth/register/email` | Public + rate limit | Create email/password account. |
| POST | `/auth/register/phone/request-otp` | Public + rate limit | Start phone registration. |
| POST | `/auth/register/phone/verify-otp` | Public + OTP proof | Create account and session. |
| POST | `/auth/login/password` | Public + rate limit | Login with email/phone and password. |
| POST | `/auth/login/phone/request-otp` | Public + rate limit | Start phone login. |
| POST | `/auth/login/phone/verify-otp` | Public + OTP proof | Issue token pair. |
| POST | `/auth/email-verification/request` | Public + rate limit | Send verification OTP. |
| POST | `/auth/email-verification/verify` | Public + OTP proof | Verify email and optionally issue session. |
| POST | `/auth/password/forgot` | Public + rate limit | Begin recovery without account enumeration. |
| POST | `/auth/password/reset/verify-otp` | Public + OTP proof | Obtain reset proof. |
| POST | `/auth/password/reset` | Public + reset proof | Set password and rotate sessions. |

## Authenticated and admin routes

| Method | Path | Authorization | Use |
|---|---|---|---|
| GET/PATCH | `/users/me` or `/auth/users/me` | Bearer | Read/update current profile. |
| GET/DELETE | `/auth/sessions...` | Bearer | List or revoke sessions. |
| PUT/POST | `/auth/password` | Bearer + sensitive re-auth | Change or set password. |
| GET/POST/PATCH/DELETE | `/admin/users...` | Named admin permission | Manage users and sessions. |
| GET/POST/PATCH/DELETE | `/admin/roles...`, `/admin/permissions...` | Named admin permission | Manage authorization data. |

Example request:

```json
{"channel":"email","email":"user@example.com","password":"<secret>","deviceName":"Mobile app"}
```

Health routes are unauthenticated probes. Never log passwords, OTPs, tokens, or authorization headers. Runtime OpenAPI is authoritative for exact request/response fields.
