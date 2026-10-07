# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

# A captive portal binds a session to a source IP and MAC, so this container
# must run with `--network host`. See deploy/docker-compose.yml.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    KMITL_STATE_DIR=/var/lib/kmitl-authen \
    KMITL_CONTROL_HOST=127.0.0.1 \
    KMITL_CONTROL_PORT=8777 \
    KMITL_LOG_JSON=true

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY kmitl_authen/ ./kmitl_authen/
COPY pyproject.toml README.md LICENSE ./
RUN pip install --no-cache-dir --no-deps .

# Non-root, but still able to write state and read its own config.
RUN useradd --system --create-home --uid 10001 kmitl \
 && mkdir -p /var/lib/kmitl-authen \
 && chown -R kmitl:kmitl /var/lib/kmitl-authen /app
USER kmitl

VOLUME ["/var/lib/kmitl-authen"]

# /healthz answers 503 while offline, so the orchestrator sees real state and
# not merely "the process is alive".
# Single line, single quotes only: a backslash-continued CMD would have its
# escapes eaten by the Dockerfile parser before the shell ever sees them.
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('KMITL_CONTROL_PORT','8777') + '/healthz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["kmitl-authen"]
CMD ["run"]
