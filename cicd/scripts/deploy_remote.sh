#!/usr/bin/env bash
# File: cicd/scripts/deploy_remote.sh
set -Eeuo pipefail

readonly IMAGE_URI="${1:?IMAGE_URI is required}"
readonly DEPLOY_DIRECTORY="${2:?DEPLOY_DIRECTORY is required}"
readonly ENV_FILE_PATH="${3:?ENV_FILE_PATH is required}"
readonly COMPOSE_PROJECT_NAME="${4:?COMPOSE_PROJECT_NAME is required}"
readonly APP_INTERNAL_PORT="${5:-5555}"
readonly APP_EXTERNAL_PORT="${6:-5555}"

readonly COMPOSE_FILE="${DEPLOY_DIRECTORY}/docker-compose.deploy.yml"

[[ -f "${ENV_FILE_PATH}" ]] || { echo "Missing environment file" >&2; exit 1; }
[[ -f "${COMPOSE_FILE}" ]] || { echo "Missing deployment compose file" >&2; exit 1; }

export IMAGE_URI ENV_FILE_PATH APP_INTERNAL_PORT APP_EXTERNAL_PORT

docker pull "${IMAGE_URI}"
docker compose \
  --project-name "${COMPOSE_PROJECT_NAME}" \
  --file "${COMPOSE_FILE}" \
  up --detach --force-recreate --remove-orphans --no-build

for attempt in $(seq 1 24); do
  if curl --fail --silent --max-time 5 \
      "http://127.0.0.1:${APP_EXTERNAL_PORT}/health/ready" >/dev/null; then
    echo "Deployment is ready"
    exit 0
  fi
  sleep 5
done

echo "Deployment readiness check failed" >&2
docker compose \
  --project-name "${COMPOSE_PROJECT_NAME}" \
  --file "${COMPOSE_FILE}" \
  logs --tail 200 api >&2
exit 1
