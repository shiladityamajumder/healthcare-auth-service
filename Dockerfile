# File: Dockerfile

FROM python:3.13-slim-bookworm AS builder

ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m venv "$VIRTUAL_ENV"
WORKDIR /build
COPY requirements.txt ./
RUN python -m pip install --requirement requirements.txt

FROM python:3.13-slim-bookworm AS runtime

ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PORT=5555

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app \
       --shell /usr/sbin/nologin app

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=app:app app ./app

USER app
EXPOSE 5555

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; p=os.getenv('PORT','5555'); urllib.request.urlopen(f'http://127.0.0.1:{p}/health/live',timeout=2).close()" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "exec python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-5555} --no-server-header"]
