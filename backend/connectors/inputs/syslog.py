"""
Syslog receivers: UDP (RFC 5426), TCP (RFC 6587) and TLS (RFC 5425).

TCP/TLS framing is detected per connection: octet-counting ("<len> <msg>",
used by rsyslog/syslog-ng and RFC 5425) or non-transparent framing (messages
separated by LF or NUL, used by most network devices).
"""
import asyncio
import logging
import ssl
from typing import Callable, Dict, List, Optional

from backend.connectors.config import SyslogInput
from backend.services.ingestion.stream import InboundRecord

logger = logging.getLogger("tracelog.inputs.syslog")
Submit = Callable[[List[InboundRecord]], None]


class InputStats:
    def __init__(self, name: str, kind: str, target: str):
        self.info: Dict = {"name": name, "type": kind, "listening": target, "received": 0, "bytes": 0,
                           "errors": 0, "last_error": None, "last_received_at": None, "peers": 0, "running": False}

    def hit(self, n: int, size: int) -> None:
        from backend.services.ingestion.stream import utcnow_iso
        self.info["received"] += n
        self.info["bytes"] += size
        self.info["last_received_at"] = utcnow_iso()

    def error(self, msg: str) -> None:
        self.info["errors"] += 1
        self.info["last_error"] = msg[:300]


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, cfg: SyslogInput, submit: Submit, stats: InputStats):
        self.cfg, self.submit, self.stats = cfg, submit, stats

    def datagram_received(self, data: bytes, addr) -> None:
        data = data[: self.cfg.max_message_bytes]
        # RFC 5426 carries one message per datagram; some relays batch several, one per line.
        parts = [data]
        if b"\n" in data.rstrip(b"\n"):
            lines = [l for l in data.split(b"\n") if l.strip()]
            if len(lines) > 1 and all(l.startswith(b"<") for l in lines):
                parts = lines
        recs = [InboundRecord(raw=p, transport="syslog-udp", input_name=self.cfg.name, peer_ip=addr[0],
                              peer_port=addr[1]) for p in parts]
        self.stats.hit(len(recs), len(data))
        self.submit(recs)

    def error_received(self, exc) -> None:
        self.stats.error(str(exc))


class SyslogStreamParser:
    """Incremental RFC 6587 framing parser for one TCP/TLS connection."""

    def __init__(self, max_bytes: int):
        self.buf = b""
        self.max = max_bytes

    def feed(self, data: bytes) -> List[bytes]:
        self.buf += data
        out: List[bytes] = []
        while self.buf:
            head = self.buf.lstrip(b"\r\n\x00")
            if head is not self.buf:
                self.buf = head
                if not self.buf:
                    break
            sp = self.buf.find(b" ", 0, 12)
            if sp > 0 and self.buf[:sp].isdigit():  # octet counting
                n = int(self.buf[:sp])
                if len(self.buf) < sp + 1 + n:
                    if n > self.max:  # refuse runaway frames: fall back to line framing
                        self.buf = self.buf[sp + 1:]
                        continue
                    break
                out.append(self.buf[sp + 1: sp + 1 + n])
                self.buf = self.buf[sp + 1 + n:]
                continue
            idx = min((i for i in (self.buf.find(b"\n"), self.buf.find(b"\x00")) if i >= 0), default=-1)
            if idx < 0:
                if len(self.buf) > self.max:  # no delimiter within the size limit: emit what we have
                    out.append(self.buf[: self.max])
                    self.buf = self.buf[self.max:]
                    continue
                break
            out.append(self.buf[:idx])
            self.buf = self.buf[idx + 1:]
        return [m for m in out if m.strip()]

    def flush(self) -> List[bytes]:
        rest, self.buf = self.buf, b""
        return [rest] if rest.strip() else []


class SyslogListener:
    def __init__(self, cfg: SyslogInput, submit: Submit):
        self.cfg, self.submit = cfg, submit
        self.stats = InputStats(cfg.name, f"syslog-{cfg.protocol}", f"{cfg.protocol}://{cfg.host}:{cfg.port}")
        self._transport = None
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            if self.cfg.protocol == "udp":
                self._transport, _ = await loop.create_datagram_endpoint(
                    lambda: _UdpProtocol(self.cfg, self.submit, self.stats), local_addr=(self.cfg.host, self.cfg.port))
            else:
                ssl_ctx = None
                if self.cfg.protocol == "tls":
                    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ssl_ctx.load_cert_chain(self.cfg.certfile, self.cfg.keyfile)
                    if self.cfg.client_ca:
                        ssl_ctx.load_verify_locations(self.cfg.client_ca)
                        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
                self._server = await asyncio.start_server(self._handle, self.cfg.host, self.cfg.port, ssl=ssl_ctx)
            self.stats.info["running"] = True
            logger.info("syslog %s listening on %s:%s", self.cfg.protocol, self.cfg.host, self.cfg.port)
        except Exception as exc:
            self.stats.error(f"could not start: {exc}")
            logger.error("syslog input %s failed to start: %s", self.cfg.name, exc)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        parser = SyslogStreamParser(self.cfg.max_message_bytes)
        transport = f"syslog-{self.cfg.protocol}"
        self.stats.info["peers"] += 1
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                msgs = parser.feed(data)
                if msgs:
                    self.stats.hit(len(msgs), len(data))
                    self.submit([InboundRecord(raw=m, transport=transport, input_name=self.cfg.name,
                                               peer_ip=peer[0], peer_port=peer[1]) for m in msgs])
            tail = parser.flush()
            if tail:
                self.stats.hit(len(tail), 0)
                self.submit([InboundRecord(raw=m, transport=transport, input_name=self.cfg.name, peer_ip=peer[0],
                                           peer_port=peer[1]) for m in tail])
        except (ConnectionError, ssl.SSLError) as exc:
            self.stats.error(f"{peer[0]}: {exc}")
        finally:
            self.stats.info["peers"] -= 1
            writer.close()

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        self.stats.info["running"] = False
