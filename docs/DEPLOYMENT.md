# Pharmacy Identity Service Deployment Runbook

## Scope

This runbook covers local execution, container deployment, release preparation, health verification, monitoring, and rollback for Pharmacy Identity Service.

The API container runs only the FastAPI process. PostgreSQL, Redis, optional MongoDB, notification providers, secrets, and database migrations are external responsibilities. Runtime settings and validation rules are documented in [`.env.example`](../.env.example).

## Prerequisites

- Python 3.12+
- PostgreSQL with the matching `healthcare_db` migrations applied
- Redis for production rate limiting
- An approved email/SMS provider for production OTP delivery
- Docker Compose v2 when using containers
- Access to the deployment platform’s secret manager

PostgreSQL must expose a direct asyncpg-compatible connection. Runtime credentials must not own schemas or hold migration privileges.

## Local setup

Run commands from the `auth_service` directory.

### 1. Create a virtual environment

Linux or macOS:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install --requirement requirements.txt
python -m pip install --requirement requirements-dev.txt
```

`pyproject.toml` contains metadata and tool configuration only. Dependencies remain in the two requirements files.

### 3. Configure the environment

Linux or macOS:

```bash
cp .env.example .env
```

Windows:

```powershell
Copy-Item .env.example .env
```

Replace development placeholders and configure externally reachable PostgreSQL and Redis URLs. Never commit `.env`.

Generate local authentication secrets and an RS256 key pair when needed:

```bash
python scripts/generate_auth_secrets.py
```

Move production output directly into a secret manager. Do not redirect private keys into tracked files or CI logs.

### 4. Prepare identity data

Apply database migrations from `healthcare_db` before running service-owned seed or bootstrap commands.

Validate the RBAC manifest without changing PostgreSQL:

```bash
python -m scripts.seed_identity_master_data --check-only
```

Apply the idempotent role, permission, and role-permission seed:

```bash
python -m scripts.seed_identity_master_data
```

Create one controlled administrator interactively:

```bash
python -m scripts.create_identity_user --help
```

For multiple initial users, create a private manifest outside source control and use:

```bash
python -m scripts.bootstrap_identity_users \
  --config /secure/path/bootstrap-users.json \
  --check-only

python -m scripts.bootstrap_identity_users \
  --config /secure/path/bootstrap-users.json
```

Delete private bootstrap material securely after use. Normal user and role administration must use protected application workflows.

### 5. Start the API

```bash
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 5555 \
  --reload
```

Verify:

```bash
curl --fail http://127.0.0.1:5555/health/live
curl --fail http://127.0.0.1:5555/health/ready
```

Swagger UI is available at `http://127.0.0.1:5555/docs` when `DOCS_ENABLED=true`.

## Docker Compose

The Compose file builds and starts one service named `api`. It does not start PostgreSQL, Redis, MongoDB, notification services, workers, or schedulers.

Before starting, ensure every configured dependency hostname is reachable from the container network. `127.0.0.1` inside the container refers to the container itself.

```bash
docker compose up --build --detach
docker compose ps
docker compose logs --follow api
```

Stop the service:

```bash
docker compose down
```

Set `PORT` before running Compose to change both the published and internal API port. The default is `5555`.

## Build an immutable image

Run the release-artifact safety check first:

```bash
python scripts/check_release_artifacts.py
```

Build from an approved clean commit:

```bash
docker build --pull \
  --tag pharmacy-identity-service:<immutable-release-tag> \
  .
```

Use a Git commit or CI build identifier, not `latest`, for production promotion.

The production image contains the `app` package and runtime dependencies only. Administrative scripts must run from a secured checkout, deployment job, or purpose-built administrative image—not by modifying the API container.

## Production infrastructure

### PostgreSQL

- Apply migrations through `healthcare_db` as a separate release step.
- Use a dedicated least-privilege application role.
- Require encrypted transport and private network access.
- Size the database for the combined pool demand of every replica.

Maximum potential API connections are:

```text
(SQL_POOL_SIZE + SQL_MAX_OVERFLOW) × process count × replica count
```

Reserve capacity for migrations, monitoring, administration, and failover.

### Redis

Production requires `RATE_LIMIT_BACKEND=redis` and an authenticated Redis URL.

- Prefer `rediss://`.
- Restrict access to application workloads.
- Use an explicit key prefix or dedicated database.
- Choose a reviewed memory policy that does not silently discard security keys.
- Monitor latency, memory, rejected connections, and command failures.

### Notification provider

Production OTP and verification flows require an approved outbound provider. Verify authentication, request timeouts, retries, idempotency, delivery status, PII handling, and secret/OTP redaction before enabling user traffic.

### Gateway and TLS

- Terminate HTTPS at a controlled gateway, ingress, or load balancer.
- Keep the API on a private network.
- Allow only required hosts and browser origins.
- Enable trusted proxy processing only for explicit proxy CIDRs.
- Strip or validate incoming tracing and forwarding headers.
- Keep administrative routes restricted to approved operators and networks.

## Required production configuration

Production startup validates security-critical combinations. At minimum:

```dotenv
ENVIRONMENT=production
DEBUG=false
DOCS_ENABLED=false
HOST_VALIDATION_ENABLED=true
LOG_JSON=true
LOG_TO_FILE=false
SQL_ECHO=false
SECURE_HEADERS_ENABLED=true
HSTS_ENABLED=true
OTP_DEV_EXPOSE_CODE=false
RATE_LIMIT_BACKEND=redis
JWT_ALGORITHM=RS256
```

Supply explicit allowed hosts and CORS origins. Inject non-placeholder PostgreSQL/Redis credentials, `AUTH_PEPPER`, RS256 keys, and notification credentials through the platform secret manager.

Do not store production secrets in source control, image layers, committed manifests, CI scripts, tickets, or logs. See [`.env.example`](../.env.example) for the complete validated configuration.

## JWT signing-key rotation

### Planned rotation

1. Generate a new RS256 key pair and key ID.
2. Add the current public key to `JWT_PREVIOUS_PUBLIC_KEYS_B64` under its existing key ID.
3. Deploy the new private key, public key, active key ID, and previous-key registry together.
4. Wait longer than the maximum accepted token lifetime.
5. Remove the retired public key in a later release.

### Emergency cutover

After a signing-key compromise, deploy a new pair and clear the previous-key registry. This immediately invalidates tokens signed by removed keys and requires users to authenticate again.

## Release sequence

1. Approve the source commit and immutable image tag.
2. Run static checks, tests, dependency auditing, and the release-artifact check.
3. Back up PostgreSQL and verify restore capability.
4. Apply the approved `healthcare_db` migration once.
5. Validate and apply identity master-data seeds.
6. Build and scan the API image.
7. Inject the reviewed production configuration and secrets.
8. Deploy new instances without routing traffic.
9. Wait for readiness on every instance.
10. Run authentication and authorization smoke tests.
11. Shift traffic gradually where supported.
12. Monitor errors, dependency health, and security signals through completion.

Never run database migrations automatically in every API replica.

## Health probes

| Probe | Endpoint | Purpose | Suggested interval |
| --- | --- | --- | ---: |
| Liveness | `/health/live` | Process restart decision | 30 seconds |
| Readiness | `/health/ready` | Traffic admission | 10 seconds |

Allow approximately 20 seconds for initial container startup and use bounded probe timeouts. Tune values from observed startup and dependency latency.

Liveness must not depend on PostgreSQL or Redis. A dependency failure should remove an instance from traffic through readiness rather than create an unnecessary restart loop.

## Verification commands

Run before promotion:

```bash
python -m compileall -q app tests scripts
ruff check app tests scripts
ruff format --check app tests scripts
mypy app
pytest -q
python scripts/check_release_artifacts.py
python -m pip_audit \
  --requirement requirements.txt \
  --requirement requirements-dev.txt
```

Run integration tests only against a dedicated, migrated test database:

```bash
RUN_POSTGRES_INTEGRATION=true \
POSTGRES_URL='postgresql+asyncpg://identity_test:encoded-password@test-db:5432/identity_test' \
pytest -m integration -q
```

Never point integration tests at staging or production.

## Post-deployment checks

- Liveness and readiness return success.
- Login issues an access/refresh pair.
- Refresh rotates the refresh token.
- Reuse of a replaced refresh token is rejected.
- Current-user authorization reflects database roles and permissions.
- Unauthorized administrative access is rejected.
- Logout revokes the active session.
- Redis-backed rate limits operate across replicas.
- Logs contain no passwords, OTP values, bearer tokens, or connection URLs.

## Monitoring and alerts

Monitor:

- HTTP latency and 4xx/5xx rates
- Login success, failure, and account lockouts
- OTP requests, verification failures, and delivery errors
- Refresh-token replay events and session revocations
- PostgreSQL pool usage, latency, and readiness failures
- Redis latency, memory, and command failures
- Administrative role and permission changes
- Container restarts and slow requests

Alert on sustained authentication failures, replay events, readiness failures, database pool exhaustion, Redis unavailability, and unexpected privilege changes.

## Rollback

1. Stop routing new traffic to the failed release.
2. Restore the previous immutable image and compatible configuration.
3. Verify liveness and readiness.
4. Run login, refresh, logout, current-user, and authorization smoke tests.
5. Restore traffic gradually and continue monitoring.

Use only the reviewed database rollback plan shipped with the migration. Prefer a forward corrective migration when rollback would lose or reinterpret data. A hard JWT key cutover cannot restore already invalidated tokens.

## Operational ownership

| Concern | Owner |
| --- | --- |
| API image and identity behavior | `auth_service` release |
| PostgreSQL schema and migrations | `healthcare_db` release |
| Runtime secrets and key custody | Deployment platform/security team |
| Redis, PostgreSQL, and networking | Infrastructure/platform team |
| Email/SMS delivery | Notification integration owner |
| Business record authorization | Downstream domain services |
