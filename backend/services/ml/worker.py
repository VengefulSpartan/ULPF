"""
The baseline detector as its own service (docker-compose.yml: detector; docs/SERVICES.md).

It opens the collector's database read-only, scores each window as it closes (baseline.run), and
sends the new flags to the collector, POST {COLLECTOR_URL}/api/ml/findings, which writes them into
the hash chain like any device's alert. So the detector can be restarted, scaled back or replaced
without touching ingestion, and there is still exactly one writer.

    python -m backend.services.ml.worker                  # every BASELINE_EVERY_MINUTES (5 when 0)
    python -m backend.services.ml.worker --once --hours 24 [--until 2026-09-21T12:00:00Z]

While it runs, GET /health on port 8000 reports the last run, for the container's health check.
"""
import argparse
import json
import logging
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

import backend.services.ml  # noqa: F401  (one BLAS thread, before numpy loads)
from backend.config import settings
from backend.services.ml import baseline, features as feat

logger = logging.getLogger("tracelog.detector")
DEFAULT_EVERY_MINUTES = 5


class CollectorWriter:
    """Sends flags to the collector instead of writing them here (this process may not write)."""

    def __init__(self, url: str, token: str = "", timeout: float = 30.0):
        self.url = url.rstrip("/") + "/api/ml/findings"
        self.token, self.timeout = token, timeout

    def __call__(self, flags: List[baseline.Flag], _database: Any, window_minutes: int) -> List[int]:
        if not flags:
            return []
        body = json.dumps({"findings": [{"uid": fl.finding_uid, "line": fl.line(window_minutes)}
                                        for fl in flags]}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                answer = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"collector refused the findings: HTTP {exc.code} {exc.read()[:200]!r}") from exc
        return list(answer.get("sequence_nums") or [])     # one entry per finding written


def _summary(schedule: baseline.Schedule) -> Dict[str, Any]:
    last = dict(schedule.last or {})
    last.pop("findings", None)
    return {"status": "healthy", "service": "TRACELOG detector", "role": "detector",
            "every_minutes": schedule.every, "collector": settings.COLLECTOR_URL,
            "last_run": last or None, "last_error": schedule.last_error}


def serve_health(schedule: baseline.Schedule, port: int = 8000) -> ThreadingHTTPServer:
    class Health(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.rstrip("/") != "/health":
                self.send_error(404)
                return
            data = json.dumps(_summary(schedule)).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("0.0.0.0", port), Health)
    threading.Thread(target=server.serve_forever, name="detector-health", daemon=True).start()
    return server


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--once", action="store_true", help="score once and exit")
    ap.add_argument("--hours", type=float, default=1.0, help="with --once: how many hours of windows to score")
    ap.add_argument("--until", help="with --once: score the windows before this ISO 8601 time instead of now")
    ap.add_argument("--port", type=int, default=8000, help="health endpoint port")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    writer = CollectorWriter(settings.COLLECTOR_URL, settings.COLLECTOR_TOKEN)
    if args.once:
        until_ms = None
        if args.until:
            from datetime import datetime
            until_ms = int(datetime.fromisoformat(args.until.replace("Z", "+00:00")).timestamp() * 1000)
        result = baseline.run(until_ms=until_ms, score_hours=args.hours, writer=writer)
        result.pop("findings", None)
        print(json.dumps(result, indent=2))
        return 0
    every = settings.BASELINE_EVERY_MINUTES or DEFAULT_EVERY_MINUTES
    schedule = baseline.Schedule(every, writer=writer)
    serve_health(schedule, args.port)
    logger.info("detector: scoring %d-minute windows every %d minutes, findings to %s",
                feat.WINDOW_MINUTES, every, settings.COLLECTOR_URL)
    schedule.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
