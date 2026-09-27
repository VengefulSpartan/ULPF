# The test suite in Linux, identical on a Linux, macOS or Windows host:
#
#   docker compose run --rm --build tests
#   docker compose run --rm --build tests python -m pytest -q tests/test_unseen_formats.py
#
# Same base image, Python and requirements as the service image (Dockerfile): the build stage below
# is the same instructions, so Docker reuses its cached wheels. What goes in is decided by
# docker/tests.Dockerfile.dockerignore, which lets the tests and docs in and still keeps secrets,
# databases, measurement results and git history out.

FROM python:3.11-slim AS wheels
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/requirements.txt
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r /tmp/requirements.txt

FROM python:3.11-slim

# the database and every scratch file go to /tmp (a tmpfs in docker-compose.yml); the code is read-only
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/src \
    HOME=/tmp \
    DATA_DIR=/tmp/tracelog-data \
    DB_PATH=/tmp/tracelog-data/ulpf.db

RUN --mount=type=bind,from=wheels,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index --find-links=/wheels /wheels/*.whl

RUN groupadd --system --gid 10001 tracelog \
 && useradd --system --uid 10001 --gid tracelog --no-create-home --shell /usr/sbin/nologin tracelog

WORKDIR /src
COPY . .
USER tracelog

CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
