"""
HTTP log receivers, mounted at the root of the API server so existing
forwarders can point at TRACELOG unchanged:

- Splunk HEC compatible:  POST /services/collector/event, /services/collector,
  /services/collector/raw, GET /services/collector/health
  (Fluent Bit, Vector, Logstash http output, Cribl, OpenTelemetry Collector
  splunk_hec exporter, Splunk forwarders with httpout)
- OpenTelemetry OTLP/HTTP logs: POST /v1/logs (JSON encoding)
- Plain lines / NDJSON:  POST /api/ingest/stream

Everything received is queued to the connector engine and processed like
syslog: archived byte-for-byte, parsed, normalised to OCSF, hash-chained and
forwarded to the configured outputs.
"""
import gzip
import json
import zlib
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from backend.connectors.engine import engine
from backend.services.ingestion.stream import InboundRecord

router = APIRouter(tags=["Log Receivers (HEC, OTLP, NDJSON)"])


def _authorised(request: Request) -> bool:
    tokens = engine.config.inputs.http.tokens
    if not tokens:
        return True
    auth = request.headers.get("authorization", "")
    for scheme in ("Splunk ", "Bearer "):
        if auth.startswith(scheme) and auth[len(scheme):].strip() in tokens:
            return True
    return request.headers.get("x-tracelog-token") in tokens


async def _body(request: Request) -> bytes:
    """Request body, decompressed when the sender used Content-Encoding gzip or deflate
    (the OpenTelemetry Collector gzips by default; Splunk forwarders and Vector can too)."""
    body = await request.body()
    enc = request.headers.get("content-encoding", "").lower()
    if "gzip" in enc:
        return gzip.decompress(body)
    if "deflate" in enc:
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)
    return body


def _peer(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _iter_json_objects(text: str) -> Iterable[Any]:
    """HEC bodies are concatenated JSON objects (not an array)."""
    dec, i, n = json.JSONDecoder(), 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        obj, i = dec.raw_decode(text, i)
        yield obj


def _submit(name: str, records: List[InboundRecord], size: int) -> None:
    if records:
        engine.submit(records)
        engine.http_hit(name, len(records), size)


def _hec_error(text: str, code: int, status: int) -> JSONResponse:
    return JSONResponse({"text": text, "code": code}, status_code=status)


@router.get("/services/collector/health")
def hec_health():
    return {"text": "HEC is healthy", "code": 17}


@router.post("/services/collector/event")
@router.post("/services/collector/event/1.0")
@router.post("/services/collector")
async def hec_event(request: Request):
    if not engine.config.inputs.http.enabled:
        return _hec_error("HEC is disabled", 1, 403)
    if not _authorised(request):
        return _hec_error("Invalid token", 4, 401)
    try:
        # JSON is UTF-8 by definition. A body that is not is refused, so the sender keeps it and can
        # retry, rather than accepted with its bytes replaced (docs/adr/0002-raw-preservation.md).
        body = (await _body(request)).decode("utf-8")
    except UnicodeDecodeError:
        return _hec_error("Invalid data format: the body is not UTF-8", 6, 400)
    if not body.strip():
        return _hec_error("No data", 5, 400)
    records = []
    try:
        for obj in _iter_json_objects(body):
            if not isinstance(obj, dict) or "event" not in obj:
                return _hec_error("Event field is required", 12, 400)
            ev = obj["event"]
            if isinstance(ev, dict) and isinstance(ev.get("_raw"), str):  # Cribl and Splunk-style wrapped events
                ev = ev["_raw"]
            # a string event is kept verbatim; an object event as that object, keys in the order sent and
            # non-ASCII kept as characters (the JSON parser does not keep the original whitespace)
            raw = ev if isinstance(ev, str) else json.dumps(ev, separators=(",", ":"), ensure_ascii=False)
            hints = {k: str(obj[k]) for k in ("host", "source", "sourcetype") if obj.get(k)}
            if "host" in hints:
                hints["hostname"] = hints["host"]
            records.append(InboundRecord(raw=raw.encode("utf-8"), transport="hec", input_name="hec",
                                         peer_ip=_peer(request), hints=hints))
    except ValueError:
        return _hec_error("Invalid data format", 6, 400)
    _submit("hec", records, len(body))
    return {"text": "Success", "code": 0}


@router.post("/services/collector/raw")
@router.post("/services/collector/raw/1.0")
async def hec_raw(request: Request):
    if not engine.config.inputs.http.enabled:
        return _hec_error("HEC is disabled", 1, 403)
    if not _authorised(request):
        return _hec_error("Invalid token", 4, 401)
    body = await _body(request)
    lines = [l for l in body.split(b"\n") if l.strip()]
    if not lines:
        return _hec_error("No data", 5, 400)
    hints = {k: v for k, v in (("hostname", request.query_params.get("host")),
                               ("sourcetype", request.query_params.get("sourcetype"))) if v}
    _submit("hec", [InboundRecord(raw=l, transport="hec", input_name="hec-raw", peer_ip=_peer(request), hints=hints)
                    for l in lines], len(body))
    return {"text": "Success", "code": 0}


def _any_value(v: Dict[str, Any]) -> Any:
    for k in ("stringValue", "boolValue", "intValue", "doubleValue"):
        if k in v:
            return v[k]
    if "kvlistValue" in v:
        return {x["key"]: _any_value(x.get("value", {})) for x in v["kvlistValue"].get("values", [])}
    if "arrayValue" in v:
        return [_any_value(x) for x in v["arrayValue"].get("values", [])]
    return None


@router.post("/v1/logs")
async def otlp_logs(request: Request):
    if not engine.config.inputs.http.enabled:
        return JSONResponse({"message": "OTLP receiver disabled"}, status_code=403)
    if not _authorised(request):
        return JSONResponse({"message": "unauthorised"}, status_code=401)
    ctype = request.headers.get("content-type", "")
    if "protobuf" in ctype:
        return JSONResponse({"message": "Use OTLP/HTTP JSON encoding (e.g. `encoding: json` in the "
                                        "Collector's otlphttp exporter)."}, status_code=415)
    body = await _body(request)
    try:
        payload = json.loads(body or b"{}")
    except ValueError:
        return JSONResponse({"message": "invalid JSON"}, status_code=400)
    records = []
    for rl in payload.get("resourceLogs", []):
        res = {a["key"]: _any_value(a.get("value", {})) for a in (rl.get("resource") or {}).get("attributes", [])}
        host = res.get("host.name") or res.get("service.name")
        for sl in rl.get("scopeLogs", []):
            for lr in sl.get("logRecords", []):
                val = _any_value(lr.get("body") or {})
                raw = val if isinstance(val, str) else json.dumps(val, separators=(",", ":"))
                if raw:
                    records.append(InboundRecord(raw=raw.encode("utf-8"), transport="otlp", input_name="otlp",
                                                 peer_ip=_peer(request), hints={"hostname": str(host)} if host else {}))
    _submit("otlp", records, len(body))
    return {"partialSuccess": {}}


@router.post("/api/ingest/stream")
async def ingest_stream(request: Request, source: Optional[str] = None, vendor: Optional[str] = None,
                        product: Optional[str] = None, message_field: Optional[str] = None):
    """Plain log lines (one per line), NDJSON, or a JSON array of strings/objects.

    `message_field` takes the original log line out of JSON objects that wrap it, e.g.
    `message` for Logstash / Beats (`http` output with `format => json_batch`) or `log` for Fluent Bit.
    """
    if not _authorised(request):
        return JSONResponse({"detail": "unauthorised"}, status_code=401)
    body = await _body(request)
    hints = {k: v for k, v in (("source_name", source), ("vendor", vendor), ("product", product)) if v}
    stripped = body.strip()
    items: List[Any] = []
    if stripped.startswith(b"["):
        try:
            items = list(json.loads(stripped))
        except ValueError:
            items = [l for l in body.split(b"\n") if l.strip()]
    else:
        items = [l for l in body.split(b"\n") if l.strip()]
    records: List[InboundRecord] = []
    for item in items:
        item_hints = hints
        if message_field and isinstance(item, bytes) and item.lstrip().startswith(b"{"):
            try:
                item = json.loads(item)
            except ValueError:
                pass
        if isinstance(item, dict) and message_field and isinstance(item.get(message_field), str):
            host = item.get("host")
            if isinstance(host, dict):  # Elastic Common Schema: host.name
                host = host.get("name") or host.get("hostname")
            if isinstance(host, str) and host:
                item_hints = {**hints, "hostname": host}
            item = item[message_field]
        if isinstance(item, str):
            item = item.encode("utf-8")
        elif not isinstance(item, bytes):
            item = json.dumps(item, separators=(",", ":")).encode("utf-8")
        records.append(InboundRecord(raw=item, transport="http", input_name="http-stream", peer_ip=_peer(request),
                                     hints=item_hints))
    _submit("http-stream", records, len(body))
    return {"accepted": len(records)}
