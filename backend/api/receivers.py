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
import json
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
@router.post("/services/collector")
async def hec_event(request: Request):
    if not engine.config.inputs.http.enabled:
        return _hec_error("HEC is disabled", 1, 403)
    if not _authorised(request):
        return _hec_error("Invalid token", 4, 401)
    body = (await request.body()).decode("utf-8", errors="replace")
    if not body.strip():
        return _hec_error("No data", 5, 400)
    records = []
    try:
        for obj in _iter_json_objects(body):
            if not isinstance(obj, dict) or "event" not in obj:
                return _hec_error("Event field is required", 12, 400)
            ev = obj["event"]
            raw = ev if isinstance(ev, str) else json.dumps(ev, separators=(",", ":"))
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
async def hec_raw(request: Request):
    if not engine.config.inputs.http.enabled:
        return _hec_error("HEC is disabled", 1, 403)
    if not _authorised(request):
        return _hec_error("Invalid token", 4, 401)
    body = await request.body()
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
    body = await request.body()
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
                        product: Optional[str] = None):
    """Plain log lines (one per line), NDJSON, or a JSON array of strings/objects."""
    if not _authorised(request):
        return JSONResponse({"detail": "unauthorised"}, status_code=401)
    body = await request.body()
    hints = {k: v for k, v in (("source_name", source), ("vendor", vendor), ("product", product)) if v}
    stripped = body.strip()
    raws: List[bytes] = []
    if stripped.startswith(b"["):
        try:
            for item in json.loads(stripped):
                raws.append(item.encode("utf-8") if isinstance(item, str)
                            else json.dumps(item, separators=(",", ":")).encode("utf-8"))
        except ValueError:
            raws = [l for l in body.split(b"\n") if l.strip()]
    else:
        raws = [l for l in body.split(b"\n") if l.strip()]
    _submit("http-stream", [InboundRecord(raw=r, transport="http", input_name="http-stream", peer_ip=_peer(request),
                                          hints=hints) for r in raws], len(body))
    return {"accepted": len(raws)}
