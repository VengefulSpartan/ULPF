"""Hosted demo: the API and two witnesses inside the dashboard's own process.

Streamlit Community Cloud runs one command, `streamlit run frontend/app.py`, in one container. With
HOSTED_DEMO=true the dashboard starts, once per process and each on a thread of its own, what
`python run_app.py` starts on a laptop:

- the API on 127.0.0.1:BACKEND_PORT: the HTTP receivers, the inputs of config/tracelog.yaml, the one
  writer, the outputs and the checkpoint timer, so every page reads it as it does on a laptop;
- two witnesses on 127.0.0.1:8101 and 8102, which countersign the checkpoints (unless WITNESS_URLS
  names witnesses elsewhere);

and, when the archive is empty, loads the demo data (the multi-vendor samples, 150 lines of a format no
vendor pack knows, and a synthetic day of FortiGate traffic with 8 attacks in it) and seals it.

What this is not, and the dashboard says so where it applies: the inputs listen inside the container, so
no device on the internet can reach them; the witnesses share the container, and its fate, with the
collector, so they show how witnessing works and protect nothing; and the archive and the keys are on the
container's disk, gone when it restarts.
"""
from __future__ import annotations

import contextlib
import importlib.util
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import requests
import uvicorn

from backend.config import BASE_DIR, settings

log = logging.getLogger("tracelog.hosted_demo")

WITNESS_PORTS = (8101, 8102)

# what the dashboard shows: where the API and the witnesses are, and what happened to the demo data
STATE: Dict[str, Any] = {"started": False, "api": None, "witnesses": [], "data": "not loaded", "error": None}

_lock = threading.Lock()
_servers: List[uvicorn.Server] = []
_threads: List[threading.Thread] = []


class _ThreadServer(uvicorn.Server):
    """uvicorn on a thread other than the main one: the process's signals stay Streamlit's."""

    @contextlib.contextmanager
    def capture_signals(self):   # uvicorn 0.29 and later
        yield

    def install_signal_handlers(self) -> None:   # earlier uvicorn
        pass


def _healthy(url: str) -> bool:
    try:
        return requests.get(url, timeout=1.0).status_code == 200
    except requests.RequestException:
        return False


def _serve(app, port: int, name: str, seconds: float = 60.0) -> str:
    base = f"http://127.0.0.1:{port}"
    if _healthy(base + "/health"):   # already running in this process
        return base
    server = _ThreadServer(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, name=f"tracelog-{name}", daemon=True)
    thread.start()
    _servers.append(server)
    _threads.append(thread)
    end = time.monotonic() + seconds
    while time.monotonic() < end and thread.is_alive():
        if _healthy(base + "/health"):
            return base
        time.sleep(0.2)
    raise RuntimeError(f"the {name} did not start on {base}")


def start(seed: bool = True, api_port: Optional[int] = None,
          witness_ports: Sequence[int] = WITNESS_PORTS) -> Dict[str, Any]:
    """Start the witnesses and the API, once. A failure is logged and kept in STATE["error"]: the dashboard
    then reads the database directly, as it does without an API."""
    with _lock:
        if STATE["started"]:
            return STATE
        try:
            from backend import witness
            from backend.main import app as api
            from backend.services.integrity import checkpoints

            if not settings.WITNESS_URLS:
                data_dir = Path(settings.DB_PATH).parent
                urls = [_serve(witness.create_app(f"witness-{i}", data_dir / f"witness-{i}"), port, f"witness-{i}")
                        for i, port in enumerate(witness_ports, start=1)]
                settings.WITNESS_URLS = ",".join(urls)
            STATE["witnesses"] = checkpoints.witness_urls()
            STATE["api"] = _serve(api, api_port or settings.BACKEND_PORT, "API")
            STATE.update(started=True, error=None)
        except Exception as exc:   # noqa: BLE001
            log.exception("hosted demo: could not start the API and witnesses")
            STATE["error"] = f"{exc.__class__.__name__}: {exc}"
            return STATE
    if seed:
        threading.Thread(target=_seed_when_empty, args=(STATE["api"],), name="tracelog-demo-data",
                         daemon=True).start()
    return STATE


def stop(timeout: float = 15.0) -> None:
    """Stop what start() started (the tests; Streamlit simply ends the process)."""
    for server in _servers:
        server.should_exit = True
    for thread in _threads:
        thread.join(timeout)
    _servers.clear()
    _threads.clear()
    STATE.update(started=False, api=None, witnesses=[], data="not loaded", error=None)


def _head(api: str) -> int:
    return int(requests.get(f"{api}/api/integrity/checkpoints", timeout=120).json().get("head_seq") or 0)


def _seed_when_empty(api: str) -> None:
    try:
        if _head(api):
            STATE["data"] = "kept"   # the archive already holds records: leave it as it is
            return
        STATE["data"] = "loading"
        load_demo_data(api)
        STATE["data"] = "loaded"
    except Exception as exc:   # noqa: BLE001
        log.exception("hosted demo: loading the demo data failed")
        STATE["data"] = f"failed: {exc.__class__.__name__}"


def _module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def demo_lines(synthetic: bool = True) -> Dict[str, List[str]]:
    """The lines the demo script sends before recording. tests/ is not in the container image, so there
    the WatchGuard lines are left out."""
    batches: Dict[str, List[str]] = {}
    samples = BASE_DIR / "tests" / "format_samples.py"
    if samples.exists():
        fs = _module(samples, "tracelog_format_samples")
        batches["watchguard"] = fs.lines(fs.watchguard(150, seed=1))
    network = BASE_DIR / "scripts" / "synthetic_network.py"
    if synthetic and network.exists():
        batches["synthetic_day"] = [line for _, line in _module(network, "tracelog_synthetic_network")
                                    .generate(seed=1).lines]
    return batches


def load_demo_data(api: str, synthetic: bool = True, wait_seconds: float = 300.0) -> Dict[str, int]:
    """Send the demo data through the API (so the one writer stores it), wait until it is chained, seal it."""
    r = requests.post(f"{api}/api/ingest/seed-samples", timeout=120)
    r.raise_for_status()
    sent = {"samples": int(r.json().get("ingested_count") or 0)}
    start_head = _head(api)
    for name, lines in demo_lines(synthetic).items():
        for i in range(0, len(lines), 5000):
            requests.post(f"{api}/api/ingest/stream", data="\n".join(lines[i:i + 5000]).encode(),
                          timeout=300).raise_for_status()
        sent[name] = len(lines)
    expected = start_head + sum(n for k, n in sent.items() if k != "samples")
    end, last, still = time.monotonic() + wait_seconds, -1, 0
    while time.monotonic() < end:   # the API accepts lines at once and stores them in the background
        head = _head(api)
        if head >= expected:
            break
        still = still + 1 if head == last else 0
        if still >= 10:   # nothing new for 20 s: merged or rejected lines; seal what is there
            break
        last = head
        time.sleep(2)
    requests.post(f"{api}/api/integrity/checkpoints/seal", timeout=300).raise_for_status()
    return sent
