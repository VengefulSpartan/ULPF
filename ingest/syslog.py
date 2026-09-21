import re
import asyncio
from typing import Dict, Any, Optional, Tuple
import structlog

from ingest.ingester import IngestPipeline

logger = structlog.get_logger()

# RFC3164 regex: <PRI>MMM DD HH:MM:SS HOSTNAME APP[PID]: MSG or <PRI>TIMESTAMP HOSTNAME MSG
RFC3164_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<message>.*)$",
    re.DOTALL
)

# RFC5424 regex: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+(?P<proc_id>\S+)\s+(?P<msg_id>\S+)\s+(?P<sd>\[.*?\]|-)\s*(?P<message>.*)$",
    re.DOTALL
)


def parse_syslog_metadata(raw_bytes: bytes) -> Dict[str, Any]:
    """Extract RFC3164 or RFC5424 Syslog priority, facility, severity, and header metadata."""
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = str(raw_bytes)

    metadata: Dict[str, Any] = {
        "format": "syslog_unknown",
        "prival": None,
        "facility": None,
        "severity": None,
    }

    # Try RFC5424 first
    m5424 = RFC5424_PATTERN.match(text)
    if m5424:
        gd = m5424.groupdict()
        pri = int(gd["pri"])
        metadata.update({
            "format": "rfc5424",
            "prival": pri,
            "facility": pri >> 3,
            "severity": pri & 7,
            "version": int(gd["version"]),
            "timestamp": gd["timestamp"],
            "hostname": gd["hostname"],
            "app_name": gd["app_name"],
            "proc_id": gd["proc_id"],
            "msg_id": gd["msg_id"],
            "structured_data": gd["sd"]
        })
        return metadata

    # Try RFC3164
    m3164 = RFC3164_PATTERN.match(text)
    if m3164:
        gd = m3164.groupdict()
        pri = int(gd["pri"])
        metadata.update({
            "format": "rfc3164",
            "prival": pri,
            "facility": pri >> 3,
            "severity": pri & 7,
            "timestamp": gd["timestamp"],
            "hostname": gd["hostname"]
        })
        return metadata

    # Check for basic <PRI> prefix
    if text.startswith("<") and ">" in text[:5]:
        try:
            pri_str = text[1:text.find(">")]
            pri = int(pri_str)
            metadata.update({
                "format": "syslog_generic",
                "prival": pri,
                "facility": pri >> 3,
                "severity": pri & 7
            })
        except ValueError:
            pass

    return metadata


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Asyncio Datagram Protocol for receiving UDP Syslog messages."""

    def __init__(self, pipeline: IngestPipeline):
        self.pipeline = pipeline

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        source_metadata = parse_syslog_metadata(data)
        source_metadata.update({
            "protocol": "syslog_udp",
            "client_ip": addr[0],
            "client_port": addr[1]
        })
        self.pipeline.process_raw_event(data, source_metadata)


class SyslogUDPListener:
    """UDP Syslog Server."""

    def __init__(self, pipeline: IngestPipeline, host: str = "0.0.0.0", port: int = 514):
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self.transport: Optional[asyncio.DatagramTransport] = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(self.pipeline),
            local_addr=(self.host, self.port)
        )
        self.transport = transport
        logger.info("syslog_udp_listener_started", host=self.host, port=self.port)

    def stop(self) -> None:
        if self.transport:
            self.transport.close()
            logger.info("syslog_udp_listener_stopped")


class SyslogTCPListener:
    """TCP Syslog Server."""

    def __init__(self, pipeline: IngestPipeline, host: str = "0.0.0.0", port: int = 1514):
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_ip, client_port = peer[0], peer[1] if peer else ("unknown", 0)

        while True:
            line = await reader.readline()
            if not line:
                break
            source_metadata = parse_syslog_metadata(line)
            source_metadata.update({
                "protocol": "syslog_tcp",
                "client_ip": client_ip,
                "client_port": client_port
            })
            self.pipeline.process_raw_event(line, source_metadata)
        
        writer.close()
        await writer.wait_closed()

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port
        )
        logger.info("syslog_tcp_listener_started", host=self.host, port=self.port)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("syslog_tcp_listener_stopped")
