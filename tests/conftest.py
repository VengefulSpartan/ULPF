"""Shared fixtures: isolated database, and local mock servers standing in for SIEMs and log tools."""
import json
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@pytest.fixture(autouse=True)
def no_learned_parsers_from_the_real_database(monkeypatch):
    """Parsers someone approved in the local TRACELOG database must not change what tests parse. Tests that use
    isolated_db (a different database) load that database's learned parsers as usual."""
    import time

    import backend.services.storage.db as db_module
    from backend.services.parser_generation import learned
    monkeypatch.setattr(learned, "RELOAD_SECONDS", 1e9)
    monkeypatch.setattr(learned, "_state", {"specs": [], "signature": None, "checked": time.monotonic(),
                                            "db": db_module.db})


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """A fresh SQLite database for code paths that use the module-level `db`."""
    import backend.services.integrity.ledger as ledger_module
    import backend.services.storage.db as db_module
    from backend.services.storage.db import Database

    database = Database(db_path=tmp_path / "tracelog-test.db")
    monkeypatch.setattr(db_module, "db", database)
    monkeypatch.setattr(ledger_module, "db", database)
    for mod in ("backend.api.connectors", "backend.api.sources", "backend.api.events", "backend.api.integrity",
                "backend.api.parsers", "backend.api.analytics", "backend.api.export"):
        m = __import__(mod, fromlist=["db"])
        if hasattr(m, "db"):
            monkeypatch.setattr(m, "db", database)
    return database


class MockHTTP:
    """Records every request; responses are chosen per path prefix."""

    def __init__(self):
        self.requests = []
        self.responses = {}  # path prefix -> (status, body dict/str)
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                mock.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers),
                                      "body": body})
                status, payload = 200, {"text": "Success", "code": 0}
                for prefix, resp in mock.responses.items():
                    if self.path.startswith(prefix):
                        status, payload = resp(body) if callable(resp) else resp
                        break
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_POST = do_PUT = do_GET = _handle

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def bodies(self, path_prefix=""):
        return [r["body"] for r in self.requests if r["path"].startswith(path_prefix)]

    def close(self):
        self.server.shutdown()


@pytest.fixture
def mock_http():
    m = MockHTTP()
    yield m
    m.close()


class Capture:
    """UDP or TCP listener that stores everything it receives."""

    def __init__(self, protocol="udp"):
        self.data = []
        cap = self
        if protocol == "udp":
            class H(socketserver.BaseRequestHandler):
                def handle(self):
                    cap.data.append(self.request[0])
            self.server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), H)
        else:
            class H(socketserver.BaseRequestHandler):
                def handle(self):
                    while True:
                        chunk = self.request.recv(65536)
                        if not chunk:
                            break
                        cap.data.append(chunk)
            self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def joined(self) -> bytes:
        return b"".join(self.data)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def udp_capture():
    c = Capture("udp")
    yield c
    c.close()


@pytest.fixture
def tcp_capture():
    c = Capture("tcp")
    yield c
    c.close()


def free_port(kind=socket.SOCK_STREAM) -> int:
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
