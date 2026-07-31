# Final Endpoint Inventory

No frontend, gateway, or downstream service consumer is present in this
repository. “External” therefore records the discoverable contract category,
not a claim that every deployed consumer has been audited.

| Method | Path | Authentication | Permission | Purpose | Internal consumer | External consumer found | Decision |
|---|---|---|---|---|---|---|---|
| GET | `/` | None | None | Service descriptor | Application | Operations | Keep |
| GET | `/health/live` | None | None | Process liveness | Health module | Orchestrator | Keep |
| GET | `/health/ready` | None | None | Traffic readiness | Health module | Orchestrator | Keep |
| GET | `/health/deep` | None | None | Bounded dependency diagnostics | Health module | Operations | Keep |
| GET | `/api/v1/auth/capabilities` | None | None | Client-safe authentication configuration | Capabilities route | Pre-auth clients | Keep |
| GET | `/api/v1/auth/.well-known/jwks.json` | None | None | Public verification keys | Token manager | JWT verifiers | Keep |
| POST | `/api/v1/auth/register/email` | None | None | Email/password registration | Registration service | Public clients | Keep |
| POST | `/api/v1/auth/register/phone/request-otp` | None | None | Phone registration challenge | Registration service | Public clients | Keep |
| POST | `/api/v1/auth/register/phone/verify-otp` | None | None | Phone account/session creation | Registration service | Public clients | Keep |
| POST | `/api/v1/auth/email-verification/request` | None | None | Email verification challenge | Verification service | Public clients | Keep |
| POST | `/api/v1/auth/email-verification/verify` | None | None | Verify email and create session | Verification service | Public clients | Keep |
| POST | `/api/v1/auth/login/password` | None | None | Password login | Login service | Public clients | Keep |
| POST | `/api/v1/auth/login/phone/request-otp` | None | None | Phone login challenge | Login service | Public clients | Keep |
| POST | `/api/v1/auth/login/phone/verify-otp` | None | None | OTP login | Login service | Public clients | Keep |
| POST | `/api/v1/auth/token/refresh` | Refresh token | None | Rotate refresh token | Token service | Authenticated clients | Keep |
| POST | `/api/v1/auth/logout` | Refresh token | None | Revoke refresh-token session | Token service | Authenticated clients | Keep |
| POST | `/api/v1/auth/logout/others` | Access token | None | Revoke other sessions | Token service | Authenticated clients | Keep |
| POST | `/api/v1/auth/logout/all` | Access token | None | Revoke all sessions | Token service | Authenticated clients | Keep |
| GET | `/api/v1/auth/sessions` | Access token | None | List owned sessions | Session service | Authenticated clients | Keep |
| DELETE | `/api/v1/auth/sessions/{session_id}` | Access token | None | Revoke an owned session | Session service | Authenticated clients | Keep |
| POST | `/api/v1/auth/password/forgot` | None | None | Request reset challenge | Password service | Public clients | Keep |
| POST | `/api/v1/auth/password/reset/verify-otp` | None | None | Exchange OTP for reset proof | Password service | Public clients | Keep |
| POST | `/api/v1/auth/password/reset` | Reset proof | None | Reset password and sessions | Password service | Public clients | Keep |
| PUT | `/api/v1/auth/password` | Access token | None | Change password | Password service | Authenticated clients | Keep |
| POST | `/api/v1/auth/password` | Access token | None | Set initial password | Password service | Authenticated clients | Keep |
| GET | `/api/v1/users/me` | Access token | None | Current profile | Current-user service | Authenticated clients | Keep |
| PATCH | `/api/v1/users/me` | Access token | None | Update current profile | Current-user service | Authenticated clients | Keep |
| GET | `/api/v1/auth/users/me/authorization` | Access token | None | Current database roles/permissions | Request principal | Authenticated clients | Keep |
| GET | `/api/v1/admin/users` | Access token | `identity.users.read` | List users | Admin-user service | Admin clients | Keep |
| GET | `/api/v1/admin/users/{user_id}` | Access token | `identity.users.read` | User detail | Admin-user service | Admin clients | Keep |
| PATCH | `/api/v1/admin/users/{user_id}/status` | Access token | `identity.users.manage` | Change account status | Admin-user service | Admin clients | Keep |
| POST | `/api/v1/admin/users/{user_id}/logout-all` | Access token | `identity.users.manage` | Revoke user sessions | Admin-user service | Admin clients | Keep |
| GET | `/api/v1/admin/roles` | Access token | `identity.roles.read` | List roles | Admin-role service | Admin clients | Keep |
| POST | `/api/v1/admin/roles` | Access token | `identity.roles.manage` | Create role | Admin-role service | Admin clients | Keep |
| GET | `/api/v1/admin/roles/{role_id}` | Access token | `identity.roles.read` | Role detail | Admin-role service | Admin clients | Keep |
| PATCH | `/api/v1/admin/roles/{role_id}` | Access token | `identity.roles.manage` | Update role | Admin-role service | Admin clients | Keep |
| DELETE | `/api/v1/admin/roles/{role_id}` | Access token | `identity.roles.manage` | Soft-delete role | Admin-role service | Admin clients | Keep |
| GET | `/api/v1/admin/permissions` | Access token | `identity.permissions.read` | List permissions | Admin-permission service | Admin clients | Keep |
| POST | `/api/v1/admin/permissions` | Access token | `identity.permissions.manage` | Create permission | Admin-permission service | Admin clients | Keep |
| GET | `/api/v1/admin/permissions/{permission_id}` | Access token | `identity.permissions.read` | Permission detail | Admin-permission service | Admin clients | Keep |
| PATCH | `/api/v1/admin/permissions/{permission_id}` | Access token | `identity.permissions.manage` | Update permission | Admin-permission service | Admin clients | Keep |
| DELETE | `/api/v1/admin/permissions/{permission_id}` | Access token | `identity.permissions.manage` | Soft-delete permission | Admin-permission service | Admin clients | Keep |
| GET | `/api/v1/admin/roles/{role_id}/permissions` | Access token | `identity.permissions.read` | Role permission mapping | Admin-permission service | Admin clients | Keep |
| PUT | `/api/v1/admin/roles/{role_id}/permissions` | Access token | `identity.permissions.manage` | Replace role permission mapping | Admin-permission service | Admin clients | Keep |
| GET | `/api/v1/admin/users/{user_id}/roles` | Access token | `identity.user_roles.read` | List user assignments | User-role service | Admin clients | Keep |
| POST | `/api/v1/admin/users/{user_id}/roles` | Access token | `identity.user_roles.manage` | Assign role | User-role service | Admin clients | Keep |
| PATCH | `/api/v1/admin/users/{user_id}/roles/{user_role_id}` | Access token | `identity.user_roles.manage` | Update assignment | User-role service | Admin clients | Keep |
| DELETE | `/api/v1/admin/users/{user_id}/roles/{user_role_id}` | Access token | `identity.user_roles.manage` | Revoke assignment | User-role service | Admin clients | Keep |
| GET | `/api/v1/users/me/roles` | Access token | None | Duplicate role projection | None after cleanup | No in-repository consumer | Remove; use current authorization |
| GET | `/api/v1/users/me/permissions` | Access token | None | Duplicate permission projection | None after cleanup | No in-repository consumer | Remove; use current authorization |

