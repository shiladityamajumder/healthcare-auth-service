<!-- File: deployment_guide.md -->

# Deployment Guide

## Required infrastructure

1. PostgreSQL reachable through `postgresql+asyncpg://`.
2. The externally migrated `identity` schema.
3. Redis for production rate limiting.
4. Seeded `customer` and `identity_admin` roles and required permissions.
5. An RS256 signing key pair.
6. A secret manager for database credentials, pepper, JWT private key, Redis credentials, and notification credentials.

## Production configuration

Production startup rejects insecure combinations. Minimum policy:

```env
ENVIRONMENT=production
DEBUG=false
DOCS_ENABLED=false
LOG_JSON=true
LOG_TO_FILE=false
SECURE_HEADERS_ENABLED=true
HSTS_ENABLED=true
HOST_VALIDATION_ENABLED=true
ALLOWED_HOSTS=["identity.example.com"]
CORS_ALLOWED_ORIGINS=["https://app.example.com"]
OTP_DEV_EXPOSE_CODE=false
JWT_ALGORITHM=RS256
RATE_LIMIT_BACKEND=redis
REDIS_URL=rediss://user:password@redis.example.com:6379/0
```

Required secrets:

```env
POSTGRES_URL=postgresql+asyncpg://user:encoded_password@database:5432/pharmacy_platform
AUTH_PEPPER=<secret-manager-value>
JWT_PRIVATE_KEY_B64=<secret-manager-value>
JWT_PUBLIC_KEY_B64=<public-key-value>
JWT_KEY_ID=identity-2026-07
```

Do not place production secrets in `.env`, image layers, Jenkinsfiles, properties files, or source control.

Terminate HTTPS only at a controlled deployment boundary and forward traffic to
the service over a protected network. HSTS is defense in depth and does not
replace TLS termination.

## Reverse proxy policy

Keep `TRUSTED_PROXY_ENABLED=false` unless the service is behind a controlled proxy. When enabled, set explicit proxy networks:

```env
TRUSTED_PROXY_ENABLED=true
TRUSTED_PROXY_CIDRS=["10.20.0.0/16","2001:db8:1234::/48"]
```

Only the direct peer is used to decide whether forwarded IP data is trustworthy. Preserve `X-Request-ID` and `X-Correlation-ID` only when they are valid UUIDs.

## Database readiness

`DATABASE_SCHEMA_CHECK=true` verifies required identity tables at startup and readiness. Keep it enabled in staging and production. Apply `SCHEMA_REQUIRED_PATCH.sql` and `RBAC_SEED_EXAMPLE.sql` through the external migration and seed service before deploying the API.

This vertical-slice refactor does not require a database migration. No MFA or API-client authentication runtime is deployed; existing ORM mappings remain unchanged for compatibility.

The external migration release must identify the exact forward and rollback
migration IDs. Apply them in staging and run the PostgreSQL integration suite
before promotion; the application repository cannot prove migration
reversibility on its own.

## Redis

Redis is security infrastructure in production. Configure TLS and authentication where available, isolate the keyspace, enforce network policy, and size memory for authentication bursts. Redis failures fail closed for protected authentication limits rather than silently bypassing limits.

## Container

```bash
docker build -t pharmacy-identity-service:release .

docker run --rm \
  --env-file /run/secrets/identity.env \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1777 \
  --security-opt no-new-privileges:true \
  -p 5555:5555 \
  pharmacy-identity-service:release
```

## Database pool sizing

Maximum connections per process are:

```text
SQL_POOL_SIZE + SQL_MAX_OVERFLOW
```

Multiply by Uvicorn workers and replicas. Reserve capacity for migrations, administration, failover, and incident response.

## Authentication contract cutover

1. Deploy Redis and verify connectivity.
2. Apply seed updates additively.
3. Deploy the API and configuration to every instance as one release.
4. Wait for `/health/ready`.
5. Validate the grouped API contract from OpenAPI.
6. Force every client to authenticate again.

This is a hard cutover. Generate a new JWT signing key and key ID, remove prior
verification keys from `JWT_PUBLIC_KEYS_B64_JSON`, and deploy that configuration
with the code. This invalidates existing access and refresh tokens and forces
every user to authenticate again. Login and refresh responses no longer contain roles or permissions;
clients must call `GET /api/v1/auth/users/me/authorization`. The removed
`/api/v1/users/me/roles` and `/api/v1/users/me/permissions` routes return 404.
`X-User-ID` and `X-Session-ID` are no longer accepted or documented.

Client-supplied non-UUID request or correlation IDs now return `400`. Coordinate this validation change with clients that previously sent arbitrary strings.

Public registration no longer accepts a `roles` property. Clients that send it
receive `422`; administrative role assignment remains available only through
the authenticated `/api/v1/admin/users/{user_id}/roles` workflow.

Canonical permission-code migrations for external policy consumers:

- `prescriptions.prescriptions.issue` → `clinical.prescriptions.issue`
- `prescriptions.prescriptions.verify` → `clinical.prescriptions.verify`
- `labs.results.record` → `diagnostics.results.record`
- `labs.results.verify` → `diagnostics.results.verify`

Update API gateway policies, downstream authorization checks, and cached token
expectations before deploying the corresponding seed manifest.

Refresh-token rotation treats persisted session device identity as immutable.
`X-Device-ID` may be omitted, but a supplied value must match
an existing binding. Sessions without a device binding are not upgraded
during refresh; users must authenticate again to establish device metadata.

## Notification delivery

Outbound email and SMS invocation remains intentionally commented at the application-service boundary. Enable it only after provider authentication, idempotency, retry, timeout, dead-letter, and privacy policies are approved. Tests use a disabled or test adapter and never require a real provider.

This disabled delivery path is a production release blocker for registration,
verification, OTP login, and password reset. A release candidate must exercise
each flow end to end with the approved provider without logging the OTP or
delivery credentials.

## Verification before promotion

```bash
python -m compileall -q app tests
ruff check app tests
ruff format --check app tests
mypy app
pytest -q
python -m pip_audit -r requirements.txt -r requirements-dev.txt
RUN_POSTGRES_INTEGRATION=true pytest -m integration -q
```
