"""
Socket and broker outputs: syslog (RFC 5424 carrying OCSF JSON, CEF or LEEF;
UDP, TCP or TLS), Graylog GELF (UDP, TCP or HTTP) and Apache Kafka.

Syslog with CEF feeds ArcSight, LogRhythm, Securonix and most SIEMs; syslog
with LEEF feeds IBM QRadar; syslog with JSON feeds Wazuh, rsyslog/syslog-ng
relays and Graylog syslog inputs.
"""
import json
import os
import socket
import ssl
import struct
import zlib
from typing import Any, Dict, List, Optional

import httpx

from .base import DeliveryError, Sink
from .formats import cef, gelf, leef, rfc5424


def _tls_context(s: Dict[str, Any]) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=s.get("ca_file"))
    if s.get("verify_tls", True) is False:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if s.get("client_cert") and s.get("client_key"):
        ctx.load_cert_chain(s["client_cert"], s["client_key"])
    return ctx


class _SocketSink(Sink):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._sock: Optional[socket.socket] = None

    def validate_settings(self):
        if not self.s.get("host") or not self.s.get("port"):
            raise ValueError(f"output '{self.cfg.name}' ({self.type_name}) needs: host, port")
        self.s["protocol"] = self.s.get("protocol", "udp").lower()

    def _connect(self) -> socket.socket:
        if self._sock is None:
            proto = self.s["protocol"]
            addr = (self.s["host"], int(self.s["port"]))
            if proto == "udp":
                self._sock = socket.socket(socket.AF_INET6 if ":" in addr[0] else socket.AF_INET, socket.SOCK_DGRAM)
            else:
                raw = socket.create_connection(addr, timeout=self.cfg.timeout_seconds)
                self._sock = _tls_context(self.s).wrap_socket(raw, server_hostname=addr[0]) if proto == "tls" else raw
        return self._sock

    def _send_frames(self, frames: List[bytes]) -> None:
        try:
            sock = self._connect()
            if self.s["protocol"] == "udp":
                for f in frames:
                    sock.sendto(f, (self.s["host"], int(self.s["port"])))
            else:
                sock.sendall(b"".join(frames))
        except OSError as exc:
            self.close()
            raise DeliveryError(f"{self.type_name} send failed: {exc}", retryable=True)

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None


class SyslogSink(_SocketSink):
    type_name = "syslog"

    def validate_settings(self):
        super().validate_settings()
        fmt = self.s.get("format", "json")
        if fmt not in ("json", "cef", "leef"):
            raise ValueError(f"output '{self.cfg.name}': format must be json, cef or leef")
        self.s["format"] = fmt

    def describe_target(self):
        return f"{self.s['protocol']}://{self.s['host']}:{self.s['port']} ({self.s['format']})"

    def _payload(self, e: Dict[str, Any]) -> str:
        fmt = self.s["format"]
        if fmt == "cef":
            body = cef(e)
        elif fmt == "leef":
            body = leef(e)
        else:
            body = json.dumps(e, default=str, separators=(",", ":"))
        return rfc5424(body, e, self.s.get("app_name", "tracelog"), int(self.s.get("facility", 20)))

    def send(self, batch):
        frames = []
        for e in batch:
            msg = self._payload(e).encode("utf-8")
            if self.s["protocol"] == "udp":
                frames.append(msg[: int(self.s.get("max_udp_bytes", 65000))])
            elif self.s.get("framing", "octet-counting") == "octet-counting":  # RFC 6587 section 3.4.1
                frames.append(str(len(msg)).encode() + b" " + msg)
            else:
                frames.append(msg + b"\n")
        self._send_frames(frames)


class GelfSink(_SocketSink):
    """Graylog Extended Log Format 1.1 over UDP (chunked, zlib), TCP (NUL-delimited) or HTTP."""
    type_name = "gelf"
    CHUNK = 8154

    def validate_settings(self):
        if self.s.get("protocol", "udp").lower() == "http":
            if not self.s.get("url"):
                raise ValueError(f"output '{self.cfg.name}' (gelf http) needs: url")
            self.s["protocol"] = "http"
            return
        super().validate_settings()

    def describe_target(self):
        if self.s["protocol"] == "http":
            return self.s["url"]
        return f"gelf+{self.s['protocol']}://{self.s['host']}:{self.s['port']}"

    def _udp_frames(self, data: bytes) -> List[bytes]:
        data = zlib.compress(data)
        if len(data) <= self.CHUNK:
            return [data]
        chunks = [data[i:i + self.CHUNK] for i in range(0, len(data), self.CHUNK)]
        if len(chunks) > 128:
            raise DeliveryError("GELF message too large for UDP (over 128 chunks)", retryable=False)
        msg_id = os.urandom(8)
        return [b"\x1e\x0f" + msg_id + struct.pack("BB", i, len(chunks)) + c for i, c in enumerate(chunks)]

    def send(self, batch):
        messages = [json.dumps(gelf(e), default=str).encode("utf-8") for e in batch]
        if self.s["protocol"] == "http":
            with httpx.Client(timeout=self.cfg.timeout_seconds, verify=self.s.get("verify_tls", True)) as c:
                for m in messages:
                    r = c.post(self.s["url"], content=m, headers={"Content-Type": "application/json"})
                    if r.status_code >= 300:
                        raise DeliveryError(f"GELF HTTP {r.status_code}", retryable=r.status_code >= 500)
            return
        if self.s["protocol"] == "udp":
            self._send_frames([f for m in messages for f in self._udp_frames(m)])
        else:
            self._send_frames([m + b"\x00" for m in messages])


class KafkaSink(Sink):
    """Apache Kafka producer (requires the optional `kafka-python-ng` package)."""
    type_name = "kafka"

    def validate_settings(self):
        if not self.s.get("bootstrap_servers") or not self.s.get("topic"):
            raise ValueError(f"output '{self.cfg.name}' (kafka) needs: bootstrap_servers, topic")
        self._producer = None

    def describe_target(self):
        return f"kafka://{','.join(self.s['bootstrap_servers'])}/{self.s['topic']}"

    def _p(self):
        if self._producer is None:
            try:
                from kafka import KafkaProducer
            except ImportError as exc:
                raise DeliveryError("kafka-python-ng is not installed", retryable=False) from exc
            self._producer = KafkaProducer(bootstrap_servers=self.s["bootstrap_servers"],
                                           value_serializer=lambda v: json.dumps(v, default=str).encode(),
                                           **(self.s.get("options") or {}))
        return self._producer

    def send(self, batch):
        p = self._p()
        for e in batch:
            key = str((e.get("src_endpoint") or {}).get("ip") or e.get("class_uid")).encode()
            p.send(self.s["topic"], value=e, key=key)
        p.flush(timeout=self.cfg.timeout_seconds)

    def close(self):
        if self._producer is not None:
            self._producer.close()
