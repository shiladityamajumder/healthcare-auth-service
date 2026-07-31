<!-- File: deployment_guide.md -->

# Pharmacy Identity Service Deployment Guide

This guide covers production deployment of the FastAPI identity service.

The application container runs only the Python API. PostgreSQL, Redis, database migrations, secrets, and notification providers are managed externally.

## Deployment model

```text
Client
  |
  v
Load balancer / API gateway / reverse proxy
  |
  v
Pharmacy Identity Service containers
  |                         |
  v                         v
PostgreSQL                Redis
```

PostgreSQL is the source of truth for users, credentials, sessions, roles, permissions, OTP state, and authentication state.

Redis is required in production for distributed rate limiting.

MongoDB is optional and must not be used as a second identity source of truth.

## Required infrastructure

Before deploying the API, provide:

1. PostgreSQL reachable through a `postgresql+asyncpg://` URL.
2. The externally migrated `identity` schema and all required tables.
3. Redis reachable through an authenticated `redis://` or `rediss://` URL.
4. Seeded roles, permissions, and role-permission mappings.
5. An RS256 private and public key pair.
6. A secret manager for database, Redis, JWT, pepper, and notification credentials.
7. A controlled HTTPS load balancer, ingress, API gateway, or reverse proxy.
8. Centralized container logs and service monitoring.

Outbound OTP delivery also requires an approved email or SMS provider.

## Production configuration

Production settings are validated during application startup. The service rejects unsafe combinations.

A minimum production configuration includes:

```dotenv
ENVIRONMENT=production
DEBUG=false
DOCS_ENABLED=false

HOST=0.0.0.0
PORT=5555

HOST_VALIDATION_ENABLED=true
ALLOWED_HOSTS=["identity.example.com"]
CORS_ALLOWED_ORIGINS=["https://app.example.com"]
CORS_ALLOW_CREDENTIALS=false

SECURE_HEADERS_ENABLED=true
HSTS_ENABLED=true

LOG_LEVEL=INFO
LOG_JSON=true
LOG_TO_FILE=false
SQL_ECHO=false
OTP_DEV_EXPOSE_CODE=false

DATABASE_STARTUP_CHECK=true
DATABASE_SCHEMA_CHECK=true
DATABASE_FAIL_FAST=true

JWT_ALGORITHM=RS256
JWT_KEY_ID=identity-2026-07
JWT_ISSUER=pharmacy-platform-identity
JWT_AUDIENCE=pharmacy-platform

RATE_LIMIT_BACKEND=redis
```

Required secrets must be injected at runtime:

```dotenv
POSTGRES_URL=postgresql+asyncpg://identity_app:encoded-password@database.example.internal:5432/pharmacy_platform
REDIS_URL=rediss://identity_user:encoded-password@redis.example.internal:6379/0
AUTH_PEPPER=<secret-manager-value>
JWT_PRIVATE_KEY_B64=<base64-encoded-private-pem>
JWT_PUBLIC_KEY_B64=<base64-encoded-public-pem>
JWT_PREVIOUS_PUBLIC_KEYS_B64={}
NOTIFICATION_API_KEY=<secret-manager-value>
```

Do not store production secrets in:

- Source control
- `.env.example`
- Docker image layers
- Jenkinsfiles
- Deployment manifests committed to the repository
- Plaintext property files
- CI logs
- Application logs

Use the deployment platform's secret manager or protected runtime environment injection.

## Database preparation

Database schema creation and migration are owned by the external migration process. The API does not create or alter the schema automatically.

Before deploying the application:

1. Back up the production database.
2. Apply the approved forward migration.
3. Confirm the required `identity` tables and indexes exist.
4. Validate the role and permission seed manifest.
5. Apply identity master-data seeds.
6. Create or synchronize required bootstrap administrators.
7. Run the PostgreSQL integration suite against the migrated schema.

The migration release must record:

- Forward migration identifier
- Rollback migration identifier
- Expected schema version
- Data backfill requirements
- Rollback limitations

See [`SCRIPT_COMMANDS.md`](SCRIPT_COMMANDS.md) for seed and bootstrap commands.

## Identity master data

Run the identity master-data seed after database migrations and before creating privileged users.

The seed operation is idempotent. It creates or updates managed roles and permissions and synchronizes their mappings with the code-defined manifest.

Do not manually create role-permission mappings that are owned by the seed manifest. A later seed run can remove stale managed mappings.

Public registration requires the configured `DEFAULT_ROLE_CODE` to exist, remain active, and appear in `SELF_REGISTRATION_ROLE_CODES`.

## JWT signing keys

Production requires RS256.

Generate keys using:

```bash
python scripts/generate_auth_secrets.py
```

Move the generated values directly into the secret manager. Do not save generated private keys in the repository.

### Planned key rotation

For a normal signing-key rotation:

1. Generate a new RS256 key pair.
2. Assign a new `JWT_KEY_ID`.
3. Move the existing public key into `JWT_PREVIOUS_PUBLIC_KEYS_B64` under its old key ID.
4. Deploy the new private key, public key, key ID, and previous-key registry together.
5. Wait longer than the maximum accepted token lifetime.
6. Remove the previous public key in a later deployment.

### Hard authentication cutover

For an intentional hard cutover:

1. Generate a new RS256 key pair and key ID.
2. Set `JWT_PREVIOUS_PUBLIC_KEYS_B64={}`.
3. Deploy the new keys to every API instance together.
4. Require every user to authenticate again.

A hard cutover immediately invalidates all tokens signed by removed keys.

## Redis requirements

Redis is security infrastructure in production because it stores distributed rate-limit state.

Production requirements:

- Use authentication.
- Prefer TLS through `rediss://`.
- Restrict network access to application workloads.
- Use a dedicated database or key prefix.
- Use `noeviction` or another reviewed memory policy that does not silently remove security keys.
- Monitor latency, memory, rejected connections, and command failures.
- Size Redis for authentication bursts and all API replicas.

The service must not silently bypass production rate limits when Redis is unavailable.

## Reverse proxy and HTTPS

Terminate HTTPS only at a controlled load balancer, ingress, gateway, or reverse proxy.

HSTS is defense in depth. It does not replace TLS termination.

Keep trusted proxy handling disabled unless the service is behind a controlled proxy:

```dotenv
TRUSTED_PROXY_ENABLED=false
TRUSTED_PROXY_CIDRS=[]
```

When enabled, configure explicit proxy networks:

```dotenv
TRUSTED_PROXY_ENABLED=true
TRUSTED_PROXY_CIDRS=["10.20.0.0/16","2001:db8:1234::/48"]
```

Only allowlisted direct peers may supply trusted forwarded client information.

Forward these tracing headers only after validating their format:

```text
X-Request-ID
X-Correlation-ID
```

The service accepts UUID values for these headers. Invalid values return `400 Bad Request`.

## Build the container image

Build from a clean repository checkout:

```bash
docker build --pull -t pharmacy-identity-service:<release-tag> .
```

Use immutable release tags such as a Git commit or CI build number:

```text
pharmacy-identity-service:git-a1b2c3d4e5f6-102
```

Do not deploy `latest` as the production release identifier.

Run the release artifact check before building:

```bash
python scripts/check_release_artifacts.py
```

The check rejects tracked environment files, private keys, database dumps, and missing secret-file ignore patterns.

## Run the API container

The image runs only the FastAPI service. PostgreSQL and Redis must already be reachable from the container network.

Example:

```bash
docker run --rm \
  --name pharmacy-identity-service \
  --env-file /run/secrets/pharmacy-identity-service.env \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1777 \
  --security-opt no-new-privileges:true \
  --stop-timeout 30 \
  -p 5555:5555 \
  pharmacy-identity-service:<release-tag>
```

The environment file in this example must be created from a protected secret source and restricted at the operating-system level. It must not be stored in the repository or image.

For Kubernetes, ECS, Nomad, or another orchestrator, inject equivalent environment values through the platform's secret-management mechanism.

## Docker Compose

The project Compose file starts only the API service.

PostgreSQL and Redis URLs must reference services reachable from the container. `127.0.0.1` inside the API container refers to the container itself.

Start the API:

```bash
docker compose up -d --build
```

Check status:

```bash
docker compose ps
```

Follow logs:

```bash
docker compose logs -f api
```

Stop the API:

```bash
docker compose down
```

## Database pool sizing

Maximum PostgreSQL connections per API process are:

```text
SQL_POOL_SIZE + SQL_MAX_OVERFLOW
```

Total potential application connections are:

```text
(SQL_POOL_SIZE + SQL_MAX_OVERFLOW) × workers × replicas
```

Reserve database capacity for:

- Migration jobs
- Administrative sessions
- Monitoring
- Failover
- Incident response
- Other services sharing the database

Start conservatively with one Uvicorn process per container unless load testing proves that additional workers are required.

## Health checks

The service exposes:

```text
GET /health/live
GET /health/ready
```

### Liveness

`/health/live` confirms that the process and event loop are responsive.

Use it for container restart decisions.

### Readiness

`/health/ready` confirms whether the instance is ready to receive traffic. With deep health checks enabled, it evaluates configured infrastructure dependencies.

Do not add an instance to the load balancer until readiness succeeds.

Recommended probe behavior:

| Probe | Initial delay | Interval | Timeout | Failure threshold |
| --- | ---: | ---: | ---: | ---: |
| Liveness | 20 seconds | 30 seconds | 3 seconds | 3 |
| Readiness | 10 seconds | 10 seconds | 5 seconds | 6 |

Adjust these values after measuring startup and dependency latency in the deployment environment.

## Deployment sequence

Use this order for staging and production:

1. Approve the release commit and immutable image tag.
2. Run linting, formatting, type checks, unit tests, contract tests, and security checks.
3. Back up PostgreSQL.
4. Apply the approved database migration.
5. Validate and apply identity master-data seeds.
6. Create or synchronize required bootstrap administrators.
7. Deploy the new API image and environment configuration.
8. Wait for `/health/ready` on every new instance.
9. Route a small percentage of traffic to the new release when the platform supports it.
10. Run post-deployment smoke tests.
11. Complete the rollout.
12. Monitor authentication failures, refresh failures, database latency, Redis errors, and HTTP error rates.

Do not run database migrations automatically in every API replica.

## Post-deployment smoke tests

Verify at minimum:

1. `/health/live` returns success.
2. `/health/ready` returns success.
3. Password login returns an access and refresh token.
4. The access token contains `sub`, `sid`, `jti`, and `token_type=access`.
5. The access token contains no roles or permissions.
6. `GET /api/v1/users/me` returns the authenticated profile.
7. `GET /api/v1/auth/users/me/authorization` returns current database-backed authorization.
8. A protected admin route rejects a user without the required permission.
9. Token refresh rotates the refresh token.
10. Reuse of the replaced refresh token is rejected.
11. Logout revokes the current session.
12. Redis-backed rate limiting is active.
13. Logs contain no passwords, OTP values, authorization headers, or raw tokens.

## Authentication contract

The service uses one authentication contract:

- `sub` is the authenticated user ID.
- There is no separate `user_id` JWT claim.
- Access tokens contain no roles or permissions.
- Login and refresh responses contain no roles or permissions.
- Roles and permissions are loaded from PostgreSQL.
- Clients obtain current authorization from:

```text
GET /api/v1/auth/users/me/authorization
```

Removed routes are not available:

```text
GET /api/v1/users/me/roles
GET /api/v1/users/me/permissions
```

The following identity assertion headers are not supported:

```text
X-User-ID
X-Session-ID
```

Public registration does not accept a client-selected `roles` property. Administrative role assignment must use the protected user-role administration APIs.

## Refresh-token and device policy

Refresh tokens rotate after every successful refresh.

Persisted session device metadata is immutable:

- `X-Device-ID` may be omitted during refresh.
- When supplied, it must match the existing session device ID.
- A mismatching device ID is rejected.
- A session without a device binding is not upgraded during refresh.
- A user must authenticate again to establish new device metadata.

Monitor refresh-token replay events as security incidents.

## Notification delivery

OTP generation, hashing, persistence, expiry, cooldown, attempt limits, and verification are implemented.

Outbound email and SMS delivery must be connected before enabling these production flows:

- Phone registration
- Phone OTP login
- Email verification
- Forgot password
- Password reset

Before enabling notification delivery, verify:

- Provider authentication
- Request timeouts
- Retry policy
- Idempotency
- Delivery status handling
- Dead-letter handling
- PII handling
- Secret redaction
- OTP redaction

A production release that depends on OTP flows is not complete until each flow passes an end-to-end provider test.

## Verification before promotion

Run from the repository root:

```bash
python -m compileall -q app tests
ruff check app tests
ruff format --check app tests
mypy app
pytest -q
python scripts/check_release_artifacts.py
python -m pip_audit -r requirements.txt -r requirements-dev.txt
```

Run PostgreSQL integration tests against a dedicated migrated test database:

```bash
RUN_POSTGRES_INTEGRATION=true \
POSTGRES_URL='postgresql+asyncpg://identity_test:encoded-password@test-database:5432/pharmacy_identity_test' \
pytest -m integration -q
```

Also verify the image:

```bash
docker build --pull -t pharmacy-identity-service:verification .
docker inspect pharmacy-identity-service:verification
```

## Rollback

Prepare rollback before production rollout.

Application rollback procedure:

1. Stop routing new traffic to the failed release.
2. Restore the previous immutable image and configuration.
3. Verify `/health/live` and `/health/ready`.
4. Run login, refresh, current-user, and authorization smoke tests.
5. Continue monitoring before restoring full traffic.

Database rollback procedure:

1. Use the rollback migration approved with the release.
2. Do not restore a database backup unless forward and rollback migrations cannot safely recover the schema.
3. Confirm whether data created by the new release is compatible with the previous application version.

A JWT signing-key hard cutover cannot be transparently reversed for tokens already invalidated. Users may need to authenticate again after rollback.

## Monitoring and alerts

Monitor:

- HTTP 4xx and 5xx rates
- Login success and failure rates
- Account lockouts
- OTP request and verification failures
- Refresh-token replay events
- Session revocations
- PostgreSQL connection usage and latency
- Redis latency and command failures
- Readiness failures
- Slow requests
- Container restarts
- Notification delivery failures

Create alerts for sustained authentication failures, refresh replay events, readiness failures, database pool exhaustion, Redis unavailability, and unexpected administrative privilege changes.

## Related documentation

- [`README.md`](README.md)
- [`Architecture.md`](Architecture.md)
- [`ENDPOINT_INVENTORY.md`](ENDPOINT_INVENTORY.md)
- [`SCRIPT_COMMANDS.md`](SCRIPT_COMMANDS.md)
- [`.env.example`](.env.example)
