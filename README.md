<div align="center">

# 🔐 Pharmacy Identity Service

**Secure authentication, session management, and database-backed authorization for the healthcare platform.**

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.128+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Async-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-Rate_Limiting-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Service_Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![JWT](https://img.shields.io/badge/JWT-RS256-000000?logo=jsonwebtokens&logoColor=white)](https://jwt.io/)

</div>

## Overview

Pharmacy Identity Service is the healthcare platform’s identity boundary. It handles registration, login, OTP verification, password recovery, token rotation, persisted sessions, user profiles, and role-based access control.

PostgreSQL is authoritative for identity and authorization data. Redis provides distributed production rate limiting. MongoDB is an optional integration and never becomes an identity source of truth.

## Documentation

| Document | Responsibility |
| --- | --- |
| [API reference](docs/API.md) | Reserved API contract and endpoint documentation. |
| [Deployment runbook](docs/DEPLOYMENT.md) | Local setup, infrastructure, releases, verification, operations, and rollback. |
| [Architecture](Architecture.md) | System boundaries, component design, request flow, persistence, and security decisions. |
| [Environment template](.env.example) | Complete runtime settings, safe defaults, constraints, examples, and production requirements. |

## Capabilities

- Email/password and phone/OTP registration
- Password and OTP login with account-lockout controls
- RS256 access tokens and rotating refresh tokens
- Session listing, revocation, logout, and replay detection
- Email verification and password recovery workflows
- Current-user profile and authorization resolution
- Administrative user, role, permission, and assignment management
- Per-route security policies and distributed rate limits

## Technology

| Area | Technology |
| --- | --- |
| API | FastAPI, Uvicorn, Pydantic 2 |
| Persistence | PostgreSQL, SQLAlchemy 2 async, asyncpg |
| Security | PyJWT, RSA/RS256, Argon2id, cryptography |
| Distributed controls | Redis-backed rate limiting |
| Optional integration | Async PyMongo/MongoDB |
| Quality | Pytest, Ruff, mypy, pip-audit |
| Runtime | Docker, non-root Python 3.12 container |

## Service boundaries

The service owns identity behavior, not platform infrastructure:

- Database schemas and migrations are owned by `healthcare_db`.
- PostgreSQL, Redis, MongoDB, and notification providers are external.
- Roles and permissions are resolved from PostgreSQL, not embedded in access tokens.
- Domain services remain responsible for record ownership and business authorization.
- The Docker Compose file starts only this API service.

## Project layout

```text
app/
├── api/            # Health routes, exception handlers, API composition
├── auth/           # Shared identity, security, policy, and workflow kernel
├── core/           # Configuration, lifecycle, logging, middleware, limits
├── db/             # PostgreSQL, Redis, MongoDB, and Unit of Work adapters
├── models/         # Runtime mappings for externally managed schemas
└── modules/        # Registration, login, sessions, users, and administration

scripts/            # Secret generation, RBAC seed, bootstrap, release checks
tests/              # Unit, contract, and opt-in PostgreSQL integration tests
```

## Getting started

1. Read the [deployment runbook](docs/DEPLOYMENT.md).
2. Copy `.env.example` to `.env` and replace development placeholders.
3. Apply the matching `healthcare_db` migrations to PostgreSQL.
4. Install dependencies and start the API on port `5555`.

Useful local URLs when documentation is enabled:

- Service descriptor: `http://localhost:5555/`
- Swagger UI: `http://localhost:5555/docs`
- Liveness: `http://localhost:5555/health/live`
- Readiness: `http://localhost:5555/health/ready`

## Security

Never commit populated environment files, database or Redis URLs, authentication peppers, signing keys, OTP values, tokens, notification credentials, or bootstrap manifests. Production startup rejects unsafe configuration combinations; see [.env.example](.env.example) for the enforced requirements.

## License

Proprietary. Internal use only unless explicitly authorized.
