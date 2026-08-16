# Deployment runbook

This service owns identity behavior, not shared schema migrations. Apply `heathcare_db` migrations as a separate release step; never run Alembic here.

```bash
cp .env.example .env
docker compose up --build
curl http://localhost:8000/health/ready
```

Build an immutable image, inject database/signing/OTP/gateway secrets from a secret manager, run behind the gateway on a private network, and use `/health/live` and `/health/ready` as probes. Keep admin routes internal. Monitor authentication failures, rate limits, OTP delivery, latency, and dependency errors.

```text
INFO service_started service=healthcare-auth-service environment=production
INFO login_completed request_id=<uuid> user_id=<uuid>
```
