# Running TRACELOG on an air-gapped network

PS 26156 item (j): the framework must be deployable where nothing can reach the internet. This
page says what TRACELOG needs from the network (nothing outside it), how to install it with no
internet access, and how that was checked.

## What connects where

TRACELOG makes network connections only to the places you configure in `config/tracelog.yaml`:
the devices that send it logs, and the outputs it forwards to (a SIEM, a Kafka cluster, a file
share). On an air-gapped network those are inside the network. It has no licence server, no
update check, no cloud model and no telemetry.

Two things in the stack did reach out, and no longer do:

| | Before | Now |
|---|---|---|
| API docs at `/docs` | Swagger UI loaded from `cdn.jsdelivr.net`; offline the page was blank | Swagger UI 5.33.0 ships in `backend/static/swagger-ui` and is served by the API; its validator badge (`validator.swagger.io`) is off |
| Dashboard | Streamlit sent usage statistics from the viewer's browser to `data.streamlit.io` | `gatherUsageStats = false` in `.streamlit/config.toml`; the Deploy button, which links to Streamlit's cloud, is hidden |

ReDoc (`/redoc`), a second docs page that needs another CDN bundle, is no longer offered.

## Install with Docker

On a machine with internet access, from the repository:

```bash
docker compose build                                   # builds tracelog:latest
sh scripts/check_image.sh                              # optional: what is in the image, and does it run offline
docker save tracelog:latest | gzip > tracelog-image.tar.gz
```

Carry `tracelog-image.tar.gz`, `docker-compose.yml`, `config/` and `.env.example` across. On the
air-gapped host (Docker and the compose plugin installed from their offline packages):

```bash
docker load < tracelog-image.tar.gz
cp .env.example .env                                   # fill in the tokens your outputs need
docker compose up -d                                   # uses the loaded image; nothing is pulled
```

## Install without Docker

On a machine with internet access and **the same operating system, CPU architecture and Python
version** as the target:

```bash
pip download -r requirements.txt -d wheelhouse
```

Carry the repository and `wheelhouse/` across, then on the target:

```bash
python3 -m venv .venv
.venv/bin/pip install --no-index --find-links wheelhouse -r requirements.txt
.venv/bin/python run_app.py
```

## How it was checked

Both servers were started inside a Linux network namespace with only a loopback interface, so any
attempt to reach another machine fails. They ran as an unprivileged user from a read-only copy of
the code, as the container runs them. Headless Chromium, in the same namespace, loaded `/docs`
and the dashboard and recorded every request the pages made.

| | Previous build | This build |
|---|---|---|
| Requests to anything but the local machine | 3: `cdn.jsdelivr.net` (Swagger UI CSS and JS), `data.streamlit.io/metrics.json` | **none** |
| `/docs` offline | blank page, 0 endpoints | **54 endpoints rendered** |
| Dashboard offline | rendered | rendered |
| Container health check (`scripts/healthcheck.py`) | — | passes |
| Writes outside `data/` and the home directory | — | none (code tree read-only) |

`tests/test_airgap.py` keeps it that way in every test run: the telemetry setting, that `/docs`
references only local files, that the Swagger UI files are the pinned upstream files (by SHA-256),
and that no page or service references a CDN or font host. `tests/test_container.py` holds the
image to the same standard: no secrets, data or history in it, not root, one process per container.

## Developer tools that do use the internet

Not part of the running service: `scripts/evaluate_public_samples.py` fetches public sample logs
from GitHub. On an air-gapped machine, copy `data/public_samples/` across and run it with
`--no-fetch`.
