<!-- File: script_commands.md -->

# Project Script Commands

This document explains every Python script included with the Pharmacy Identity Service, what it is used for, when to run it, and the required command.

Run all commands from the repository root with the project virtual environment activated.

```bash
cd auth_service
source .venv/bin/activate
```

Windows PowerShell:

```powershell
cd auth_service
.venv\Scripts\Activate.ps1
```

The scripts read configuration from environment variables and the optional local `.env` file through `AppSettings`.

## Script overview

| Script | Purpose | Requires PostgreSQL | Safe to repeat |
| --- | --- | ---: | ---: |
| `generate_auth_secrets.py` | Generate authentication secrets and an RS256 key pair | No | Yes |
| `seed_identity_master_data.py` | Create or synchronize managed roles, permissions, and role-permission mappings | Yes, except `--check-only` | Yes |
| `create_identity_user.py` | Interactively create one verified identity user and assign roles | Yes | No |
| `bootstrap_identity_users.py` | Create or synchronize multiple privileged users from a private JSON manifest | Yes, except `--check-only` | Yes |
| `check_release_artifacts.py` | Detect tracked secret files and unsafe release inputs | No | Yes |

## Recommended execution order

### First environment setup

```text
1. Apply external database migrations
2. Generate authentication secrets
3. Validate the role and permission manifest
4. Seed identity master data
5. Create or bootstrap the first privileged administrator
6. Run release and verification checks
7. Start the API
```

### Commands

```bash
python scripts/generate_auth_secrets.py
python -m scripts.seed_identity_master_data --check-only
python -m scripts.seed_identity_master_data
python -m scripts.create_identity_user --help
python scripts/check_release_artifacts.py
```

Use `bootstrap_identity_users.py` instead of `create_identity_user.py` when several initial users must be synchronized from an approved private manifest.

## 1. Generate authentication secrets

### Script

```text
scripts/generate_auth_secrets.py
```

### Purpose

Generates:

- `AUTH_PEPPER`
- Development `JWT_SECRET`
- Base64-encoded RS256 private key
- Base64-encoded RS256 public key
- A new JWT key ID

### Command

```bash
python scripts/generate_auth_secrets.py
```

### Output example

```dotenv
AUTH_PEPPER=<generated-value>
JWT_SECRET=<generated-value>
JWT_PRIVATE_KEY_B64=<generated-value>
JWT_PUBLIC_KEY_B64=<generated-value>
JWT_KEY_ID=auth-<generated-id>
```

### When to run

Run this script:

- During initial environment setup
- When creating a new production signing key
- During planned JWT key rotation
- After a secret compromise
- When replacing development placeholders

### Important rules

- Do not redirect production output into a tracked file.
- Do not paste private keys into tickets, chat, email, or CI logs.
- Move generated production values directly into the secret manager.
- Use `JWT_ALGORITHM=RS256` in production.
- `JWT_SECRET` is used only with HS256 development or testing configurations.

## 2. Validate and seed identity master data

### Script

```text
scripts/seed_identity_master_data.py
```

### Purpose

Creates or updates managed:

- Roles
- Permissions
- Role-permission mappings

The script is idempotent and transactionally synchronizes managed role-permission mappings with the code-defined manifest.

It does not:

- Create users
- Assign roles to users
- Create organization memberships
- Create API clients
- Apply database schema migrations

### Prerequisites

- `POSTGRES_URL` must be configured for execution mode.
- The externally managed `identity` schema must already be migrated.
- Required database tables must exist.

### Validate without PostgreSQL

```bash
python -m scripts.seed_identity_master_data --check-only
```

Use this in local development and CI to validate the static manifest without changing a database.

### Apply the seed

```bash
python -m scripts.seed_identity_master_data
```

### When to run

Run after:

- Initial database migration
- Adding or changing managed permissions
- Adding or changing managed roles
- Changing managed role-permission mappings

### Important rules

- Review seed changes before production deployment.
- Run `--check-only` before applying the seed.
- Back up production data before major RBAC changes.
- The seed can remove stale mappings for managed roles when they are no longer in the manifest.
- Domain services must still enforce record ownership, facility scope, purpose of use, and other business rules.

## 3. Create one identity user interactively

### Script

```text
scripts/create_identity_user.py
```

### Purpose

Creates one active, verified user with:

- Email
- Phone number
- Password hash
- User profile
- Password-history entry
- One or more global role assignments

The password is requested through a secure interactive prompt and is not accepted as a command argument.

### Prerequisites

- `POSTGRES_URL` must be configured.
- Database migrations must be complete.
- Required roles must already exist.
- Run `seed_identity_master_data.py` first.

### Show available options

```bash
python -m scripts.create_identity_user --help
```

### Create one administrator

```bash
python -m scripts.create_identity_user \
  --email admin@example.com \
  --phone-country-code +91 \
  --phone-number 9876543210 \
  --first-name Admin \
  --last-name User \
  --preferred-name "Platform Admin" \
  --preferred-locale en-IN \
  --timezone Asia/Kolkata \
  --role platform_admin
```

The command then prompts for:

```text
Password:
Confirm password:
```

### Assign multiple roles

Repeat `--role`:

```bash
python -m scripts.create_identity_user \
  --email admin@example.com \
  --phone-country-code +91 \
  --phone-number 9876543210 \
  --first-name Admin \
  --role identity_admin \
  --role compliance_officer
```

### Windows PowerShell example

```powershell
python -m scripts.create_identity_user `
  --email admin@example.com `
  --phone-country-code +91 `
  --phone-number 9876543210 `
  --first-name Admin `
  --last-name User `
  --role platform_admin
```

### When to use

Use this script when:

- Creating the first administrator manually
- Creating one emergency administrative account
- Creating one controlled test account

### Important rules

- This script is not idempotent.
- It fails when the email or phone number already belongs to another user.
- It creates an active account with email and phone already verified.
- Use protected administrative APIs for normal ongoing user and role management.
- Do not use shared administrator credentials.

## 4. Bootstrap multiple identity users

### Script

```text
scripts/bootstrap_identity_users.py
```

### Purpose

Creates or synchronizes multiple initial privileged users from a JSON manifest.

The script is idempotent by normalized email and can synchronize:

- User records
- Profiles
- Missing role assignments
- Passwords only when `--rotate-passwords` is explicitly supplied

### Prerequisites

- `POSTGRES_URL` must be configured for execution mode.
- Database migrations must be complete.
- Required roles must already be seeded.
- Create a private manifest based on `bootstrap_users.example.json`.

### Create a private manifest

```bash
cp bootstrap_users.example.json bootstrap_users.private.json
```

Edit the private file with approved user details and unique passwords.

Do not commit the private manifest.

### Validate the manifest without PostgreSQL

```bash
python -m scripts.bootstrap_identity_users \
  --config bootstrap_users.private.json \
  --check-only
```

### Create or synchronize users

```bash
python -m scripts.bootstrap_identity_users \
  --config bootstrap_users.private.json
```

### Rotate passwords for existing manifest users

```bash
python -m scripts.bootstrap_identity_users \
  --config bootstrap_users.private.json \
  --rotate-passwords
```

### When to use

Use this script for:

- Initial platform bootstrap
- Controlled staging environment setup
- Disaster-recovery administrator recreation
- Synchronizing an approved initial administrator set

### Important rules

- The manifest contains plaintext passwords.
- Store it outside source control with restricted file permissions.
- Delete it securely after the bootstrap is complete.
- Do not use example passwords in shared environments.
- Do not use `--rotate-passwords` unless password rotation is explicitly intended.
- Missing role codes cause the operation to fail. Run the master-data seed first.
- Review all privileged role assignments before execution.

## 5. Check release artifacts for secrets

### Script

```text
scripts/check_release_artifacts.py
```

### Purpose

Fails when tracked release inputs contain forbidden secret artifacts.

It checks for:

- Tracked `.env` files other than `.env.example`
- Private key files
- Certificate containers
- Database backups and dumps
- Private-key markers inside tracked files
- Required secret patterns in `.gitignore`
- Required secret patterns in `.dockerignore`

### Prerequisite

The command must run inside a Git repository with Git installed.

### Command

```bash
python scripts/check_release_artifacts.py
```

### Expected success output

```text
Release artifact secret-file check passed.
```

### When to run

Run:

- Before every release build
- In CI
- Before creating a source archive
- Before sharing the repository
- After changing `.gitignore` or `.dockerignore`

### Important limitation

The script checks tracked repository inputs. It does not replace a full secret scanner for Git history, container layers, CI logs, or external artifact storage.

## Common supporting commands

These are not scripts under `scripts/`, but they are part of normal project operation.

### Validate application configuration

```bash
python -c "from app.core.config import AppSettings; AppSettings(); print('Configuration valid')"
```

This validates `.env` and all cross-field security rules without starting FastAPI.

### Compile Python files

```bash
python -m compileall -q app tests scripts
```

### Run all tests

```bash
pytest -q
```

### Run linting

```bash
ruff check app tests scripts
```

### Check formatting

```bash
ruff format --check app tests scripts
```

### Run type checking

```bash
mypy app
```

### Run dependency audit

```bash
python -m pip_audit -r requirements.txt -r requirements-dev.txt
```

### Run PostgreSQL integration tests

```bash
RUN_POSTGRES_INTEGRATION=true \
POSTGRES_URL='postgresql+asyncpg://identity_test:encoded-password@127.0.0.1:5432/pharmacy_identity_test' \
pytest -m integration -q
```

### Start the API locally

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5555 --reload
```

### Build the API image

```bash
docker build --pull -t pharmacy-identity-service:local .
```

### Start the API with Docker Compose

```bash
docker compose up -d --build
```

The Compose configuration starts only the Python API. PostgreSQL and Redis must be available externally through `.env` URLs.

## Production bootstrap checklist

Use this checklist for a new production environment:

```text
[ ] External database migrations applied
[ ] PostgreSQL schema checks passed
[ ] Production secrets generated and stored in the secret manager
[ ] RS256 configured
[ ] Redis configured with authentication and TLS where available
[ ] Master-data seed validated with --check-only
[ ] Master-data seed applied
[ ] Initial administrator created or bootstrapped
[ ] Private bootstrap manifest deleted
[ ] Release artifact check passed
[ ] Unit and contract tests passed
[ ] PostgreSQL integration tests passed
[ ] Dependency audit passed
[ ] Docker image built from an approved commit
[ ] API readiness check passed
```

## Script execution inside Docker

The production Docker image copies only the `app` package. It does not include the `scripts` directory.

Therefore, run administrative scripts from:

- A secured source checkout with a virtual environment
- A dedicated CI or deployment job
- A separate reviewed administrative image that explicitly includes the scripts

Do not modify the production API container interactively to run bootstrap or seed operations.

## Related documentation

- [`README.md`](README.md)
- [`deployment_guide.md`](deployment_guide.md)
- [`Architecture.md`](Architecture.md)
- [`ENDPOINT_INVENTORY.md`](ENDPOINT_INVENTORY.md)
- [`.env.example`](.env.example)
