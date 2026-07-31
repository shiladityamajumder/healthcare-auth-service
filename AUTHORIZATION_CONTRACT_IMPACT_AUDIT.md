# Authorization Contract Impact Audit

## Scope and confidence

This audit covers every file available in this repository. The workspace
contains the FastAPI identity service, tests, deployment assets, and identity
seed/bootstrap scripts. It contains no browser/mobile frontend, API gateway
implementation, token-introspection client, or downstream business service.

Consequently, the in-repository compatibility path is verified, but removal of
version 1 cannot be declared safe until external consumers are inventoried and
tested.

## Consumer impact matrix

`JWT-P`, `JWT-R`, and `Login-P` respectively mean reading permissions from an
access token, roles from an access token, and permissions/roles from a login
response.

| Classification | File and exact consumer | JWT-P | Login-P | JWT-R | Backend authorization | UI only | Breakage if permissions disappear | Required migration | Priority |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Security-critical backend consumer | `app/auth/security/tokens.py` — `TokenManager.decode`, `_validate_payload_contract`, `_validate_access_claims` | Validates v1 presence; rejects v2 presence | No | Validates v1 presence and optional v2 role array | Establishes the trusted token contract; does not decide a route permission | No | An unversioned/malformed change would reject tokens; permissive validation could create ambiguity | Keep strict version-specific validation. Treat missing `ver` as legacy v1 only. Reject missing v1 arrays and any v2 permission array | P0 |
| Security-critical backend consumer | `app/auth/request_context/dependencies.py` — `get_current_user_principal` | Yes for v1; no for v2 | No | Yes for v1/v2 hints | Builds the authoritative `UserPrincipal` | No | Removing v1 permissions without changing `ver` fails validation. Trusting absent v2 permissions would deny legitimate access or invite a bypass workaround | For v2, require active persisted session and load current database authorization before returning the principal | P0 |
| Security-critical backend consumer | `app/auth/route_security.py` — `secure_route`, `_authorize` | Indirectly through `UserPrincipal` | No | Indirectly through `UserPrincipal` | Yes; this is the active route authorization decision | No | Empty permissions deny admin operations; stale v1 snapshots may delay revocation when database refresh is disabled | Keep fail-closed set comparison. Consume only the resolved principal, never raw JWT dictionaries | P0 |
| Security-critical backend consumer | `app/modules/admin_users/dependencies.py` — `AdminUserReadAccess`, `AdminUserManageAccess` | Indirect | No | No | Requires `identity.users.read/manage` | No | Admin user reads/mutations return 403 if authorization is absent | Database authorization through the v2 principal; no route change | P0 |
| Security-critical backend consumer | `app/modules/admin_roles/dependencies.py` — `RoleReadAccess`, `RoleManageAccess` | Indirect | No | No | Requires `identity.roles.read/manage` | No | Role administration returns 403 | Database authorization through the v2 principal | P0 |
| Security-critical backend consumer | `app/modules/admin_permissions/dependencies.py` — `PermissionReadAccess`, `PermissionManageAccess` | Indirect | No | No | Requires `identity.permissions.read/manage` | No | Permission and role-permission administration returns 403 | Database authorization through the v2 principal | P0 |
| Security-critical backend consumer | `app/modules/admin_user_roles/dependencies.py` — `UserRoleReadAccess`, `UserRoleManageAccess` | Indirect | No | No | Requires `identity.user_roles.read/manage` | No | User-role administration returns 403 | Database authorization through the v2 principal | P0 |
| Backend convenience consumer | `app/modules/current_user/routes.py`, `service.py`, `repositories.py` — `get_current_authorization`, `CurrentUserService.authorization` | No | No | No | Endpoint authentication/session enforcement is real; returned lists are informational to the caller | No | No break from token claim removal; it resolves current database state | Protected authorization endpoint; callers may cache only with bounded TTL/invalidation | P0 |
| Backend convenience consumer | Same files — `get_current_user_roles`, `get_current_user_permissions`, `CurrentUserService.roles/permissions` | No | No | No | No additional authorization decision beyond access control | No | External callers using the old endpoints continue to work | Migrate to consolidated protected endpoint; retain deprecated projections during v1 window | P1 |
| Backend convenience consumer | `app/modules/current_user/service.py` — `get`, `update` | No | No | No | No route-level permission decision | No | External consumers may rely on `UserResponse.roles/permissions` | Keep v1 response unchanged; migrate clients to minimal profile plus authorization endpoint | P1 |
| Backend convenience consumer | `app/modules/admin_users/service.py` — `list_users`, `get_user`, `update_status` response projection | No | No | No | Route is authorized separately; these lists describe target users | No | Admin clients may lose displayed target-user authorization | Keep admin DTO unchanged until a separately versioned admin contract exists | P1 |
| Backend convenience consumer | `app/modules/login/service.py` — `_LoginBase._issue_tokens`; `app/modules/login/routes.py` login endpoints | No | Produces both fields in v1; does not consume them | No | No | No | External login clients may fail parsing/bootstrap/navigation if fields disappear | Keep explicit v1/v2 response DTOs and v1 default. UI migrates to protected authorization bootstrap | P0 external |
| Backend convenience consumer | `app/modules/token_management/service.py` — `TokenManagementService.refresh`; refresh route | No for access authorization; decodes refresh `sub/sid/fam` | Produces v1 response fields | No | Refresh session/account validation is security-critical, but response authorization lists are not | No | Refresh clients may lose authorization/bootstrap refresh behavior | Keep v1/v2 response DTOs and v1 default; migrate clients with login consumers | P0 external |
| Backend convenience consumer | `app/modules/registration/service.py`, `email_verification/service.py`, `password_management/service.py` and their routes | No | Produce v1 `UserResponse`/`TokenPairResponse` fields | No | No authorization decision from those response fields | No | Clients may assume every session-creating workflow returns identical authorization data | Intentionally retain v1 contracts until each surface receives an explicit versioned migration | P1 |
| Backend convenience consumer | `app/auth/workflows/session_tokens.py` — `SessionTokenIssuer.issue` | No | No | No | Passes database claims to token issuance | No | Removing parameters prematurely breaks all token-creating workflows | Keep issuer interface during dual issuance; TokenManager selects the versioned claim set | P1 |
| Dead or unused code | `app/auth/authorization/dependencies.py` — `require_permissions`, `require_roles` | Indirect through principal | No | Indirect | Would authorize if wired, but repository search finds no caller/import | No | No current runtime break; deleting it could affect undocumented imports outside the repository | Retain during migration or formally deprecate as a public Python interface | P3 |
| Dead or unused code | `app/auth/request_context/principals.py` — `UserPrincipal.has_permission`, `has_role` | Indirect | No | Indirect | Helpers are not called in the available workspace | No | No internal break; external Python imports are unknown | Retain as compatibility helpers; do not base v2 behavior on missing raw claims | P3 |
| Logging or analytics consumer | `app/core/logging.py`, `app/core/middleware.py`, `app/utils/debug.py` | No | No | No | No | No | No authorization impact; only credential/header redaction and request logging are present | No replacement | P3 |
| Backend convenience consumer | `scripts/seed_identity_master_data.py` and `tests/unit/test_identity_master_seed.py` | No | No | No | Defines canonical RBAC vocabulary; does not authorize a request | No | Renaming codes breaks route policies and external policy stores | Treat seed codes as versioned external contracts; coordinate aliases/migrations | P1 |
| Backend convenience consumer | `app/core/config.py`, `app/modules/registration/service.py` — `DEFAULT_ROLE_CODE`, `SELF_REGISTRATION_ROLE_CODES` | No | No | No | Controls safe self-registration assignment | No | Uncoordinated role rename blocks registration | Validate the configured role against active database state and self-registration allowlist | P1 |
| Backend convenience consumer | `bootstrap_users.example.json`, `scripts/bootstrap_identity_users.py`, `scripts/create_identity_user.py` | No | No | No | Administrative provisioning, not request authorization | No | Role-code changes can make bootstrap fail or grant an unintended role if mappings drift | Validate role existence and review privileged hardcoded role codes on every seed change | P1 |
| Unknown and requiring manual verification | Frontend/mobile clients not present in the workspace | Unknown | Likely | Unknown | Must be no | Likely | UI bootstrap, navigation, feature visibility, or local caches may break. UI checks never constitute security | Protected authorization endpoint or frontend bootstrap authorization data; clear cache on login/logout/refresh and RBAC changes | P0 manual |
| Unknown and requiring manual verification | API gateways/reverse proxies not present in the workspace | Unknown | No | Unknown | Potentially | No | A gateway that requires a `permissions` claim may deny all v2 traffic; one that treats absence as allow would create a bypass | Validate v1/v2 explicitly; prefer audience-specific entitlements or authenticated authorization lookup; missing claims deny | P0 manual |
| Unknown and requiring manual verification | Downstream services/service-to-service clients not present in the workspace | Unknown | Unknown | Unknown | Potentially | No | Local JWT middleware may deny requests, silently skip checks, or continue using stale global grants | Inventory each audience. Use database authorization, authenticated authorization service, or narrow audience-specific claims | P0 manual |
| Unknown and requiring manual verification | External authorization caches/analytics/token-introspection systems not present in the workspace | Unknown | Unknown | Unknown | Potentially | No | Cached v1 grants may outlive role revocation; schema-dependent pipelines may reject v2 | Key caches by issuer, subject, session, audience, and token version; bounded TTL plus role-change/session-revocation invalidation | P0 manual |

## Findings

- No in-repository frontend permission rendering exists.
- No in-repository authorization cache exists. Redis is used for rate limiting,
  not cached user authorization.
- No token-introspection endpoint or client exists.
- No active API-client/service-to-service authentication workflow exists;
  only database mappings and seed permissions are present.
- The only direct access-token decode path is `TokenManager.decode` followed by
  `get_current_user_principal`.
- Refresh and password-reset decoding consume purpose-specific tokens and do
  not read access-token roles or permissions.
- Authorization middleware fails closed by comparing required codes against
  immutable principal sets.

## Migration contract

### Accepted tokens

1. Legacy access tokens without `ver` are version 1.
2. Version 1 requires `roles`, `permissions`, `sid`, and `amr`.
3. Version 2 requires `sid`, `amr`, and `ver: 2`; `permissions` is forbidden.
4. Version 2 coarse roles are optional hints. This service replaces them with
   current database roles before authorization.
5. Unknown, boolean, string, or unsupported versions are rejected.
6. Algorithm, `kid`, issuer, audience, expiry, token type, subject, and JWT ID
   validation remains identical across versions.

### Missing-claim behavior

Missing authorization never means allow. A version 1 token missing its required
authorization arrays is invalid. A version 2 principal must obtain database
authorization successfully; database/session failure fails closed rather than
falling back to token hints.

### Cache contract

The auth service does not cache effective authorization. A downstream cache
must:

- be scoped by issuer, audience, subject, session ID, and token version;
- have a documented TTL no greater than the shorter of the access-token
  remaining lifetime and the downstream revocation target;
- invalidate on user-role assignment create/update/delete, role soft-delete,
  role-permission replacement, permission soft-delete, user deactivation, and
  session revocation;
- fail closed when authorization cannot be refreshed;
- never reuse authorization across tenants or scopes.

Until an event/outbox contract exists, downstream services must use a short
bounded TTL and re-resolve on sensitive operations.

## Exact migration order

1. Freeze version 1 issuance and response defaults.
2. Inventory every external gateway, frontend, mobile application, worker, and
   service that accepts this issuer/audience or parses login responses.
3. Add dual-version validation tests to every security-critical consumer.
4. Migrate browser/mobile bootstrap to the protected current-authorization
   endpoint. UI state remains informational.
5. Migrate backend consumers to database authorization, authenticated
   authorization lookup, or narrowly audience-specific entitlements.
6. Define cache keys, TTL, invalidation triggers, fail-closed behavior, and
   tenant/scope isolation.
7. Enable version 2 response DTOs for audited clients.
8. Canary version 2 access-token issuance for audited audiences and monitor
   authentication failures by issuer/audience/version without logging tokens.
9. Expand issuance only after every P0 consumer is verified.
10. Stop version 1 issuance.
11. Continue accepting version 1 for at least the maximum access-token TTL,
    clock-skew allowance, queued-message lifetime, and incident rollback
    window.
12. Remove version 1 only after telemetry shows no v1 traffic and owners of all
    P0 consumers sign off.

## Version 1 removal criteria

All of the following are mandatory:

- complete consumer registry with an owner for every accepted audience;
- no unverified security-critical consumer;
- no gateway or service interprets missing permissions as allow;
- frontend/mobile clients no longer require login-response authorization;
- cache invalidation and failure behavior are tested;
- zero observed version 1 traffic for the agreed observation window;
- at least one maximum token lifetime has elapsed since v1 issuance stopped;
- rollback has been exercised in staging;
- change is released as an explicitly communicated breaking contract change.

## Rollback

1. Keep validation for both versions deployed.
2. Restore `ACCESS_TOKEN_VERSION=1`.
3. Restore `AUTH_LOGIN_REFRESH_RESPONSE_VERSION=1`.
4. Do not roll back database role/permission revocations or session
   invalidations.
5. Drain/correct downstream caches keyed to version 2.
6. Preserve telemetry by version and audience to identify the failed consumer.
7. Reattempt version 2 only after the consumer fix is verified.

