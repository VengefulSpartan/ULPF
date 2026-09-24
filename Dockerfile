# TRACELOG image. One image, one process per container: the API (with the syslog, HEC and OTLP
# receivers) by default, the dashboard with `streamlit run ...` as the command. docker-compose.yml
# runs both from this image.
#
# What goes in is decided by .dockerignore: no .env, no database, no .git, no local venv.
# Secrets arrive as environment variables when the container starts. Needs BuildKit (the default
# builder since Docker 23) for the cache-free wheel install below. For an air-gapped site, build
# where there is internet and carry the image across: docs/AIRGAP.md.

# --- build stage: turn the requirements into wheels, with a compiler at hand for any package
# that has no prebuilt wheel on this platform. Nothing from this stage but the wheels survives.
FROM python:3.11-slim AS wheels
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/requirements.txt
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r /tmp/requirements.txt

# --- runtime stage: no compiler, no pip cache, not root
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HOME=/home/tracelog

# Installed from the wheels built above, offline: the runtime stage never reaches a package index.
RUN --mount=type=bind,from=wheels,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index --find-links=/wheels /wheels/*.whl

RUN groupadd --system --gid 10001 tracelog \
 && useradd --system --uid 10001 --gid tracelog --create-home --home-dir /home/tracelog \
            --shell /usr/sbin/nologin tracelog

WORKDIR /app
# The code belongs to root and is read-only to the service; only data/ is writable, and
# docker-compose.yml mounts a volume there.
COPY . .
RUN mkdir -p /app/data && chown tracelog:tracelog /app/data

USER tracelog

# 8000: API, dashboard backend, Splunk HEC and OTLP/HTTP receivers. 5514: syslog (UDP and TCP);
# unprivileged, so publish the host's 514 onto it (docker-compose.yml does). 6514: syslog over TLS.
# 8501: the dashboard, when the container runs it.
EXPOSE 8000 5514/udp 5514/tcp 6514 8501

# healthy when whichever process this container runs answers (API on 8000 or dashboard on 8501)
HEALTHCHECK --interval=30s --timeout=8s --start-period=30s --retries=3 \
    CMD ["python", "scripts/healthcheck.py"]

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
