# syntax=docker/dockerfile:1

# Build production dependencies inside an isolated virtual environment. The
# final runtime image receives the environment without build caches or source
# files that are not required by the authentication API.
FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv

RUN python -m venv "${VIRTUAL_ENV}"
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR /build

# Copy the dependency manifest before application code so dependency
# installation remains cached when only source files change.
COPY requirements.txt ./

RUN python -m pip install --upgrade pip \
    && python -m pip install --requirement requirements.txt


FROM python:3.12-slim-bookworm AS runtime

ENV APP_HOME=/app \
    HOST=0.0.0.0 \
    PATH="/opt/venv/bin:${PATH}" \
    PORT=5555 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1

WORKDIR ${APP_HOME}

# Use a fixed unprivileged UID/GID so mounted files and container security
# policies can refer to a stable runtime identity.
RUN groupadd --system --gid 10001 appgroup \
    && useradd --system --uid 10001 --gid appgroup --create-home \
        --home-dir /home/appuser --shell /usr/sbin/nologin appuser

COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appgroup app ./app

USER appuser

EXPOSE 5555

# Probe process liveness without adding curl or another runtime package. This
# endpoint does not require PostgreSQL, Redis, or MongoDB to be healthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; port = os.getenv('PORT', '5555'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health/live', timeout=3).close()" || exit 1

# Uvicorn handles SIGTERM and drains active requests during orchestrated stops.
STOPSIGNAL SIGTERM

# Shell expansion keeps HOST and PORT configurable for direct `docker run`.
# `exec` makes Uvicorn the managed process so it receives termination signals.
CMD ["sh", "-c", "exec python -m uvicorn app.main:app --host \"${HOST:-0.0.0.0}\" --port \"${PORT:-5555}\" --no-server-header"]
