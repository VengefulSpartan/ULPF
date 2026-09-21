import os
import structlog
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Response, status
from pydantic import BaseModel
from dotenv import load_dotenv

from opensearchpy import OpenSearch
from minio import Minio
from kafka import KafkaConsumer

load_dotenv()

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Universal Log Pre-processing Framework (ULPF) API",
    version="0.1.0",
    description="Air-gapped perimeter log processing, zero-touch parsing, OCSF normalization, and cross-source RCA."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class HealthCheckResponse(BaseModel):
    status: str
    services: Dict[str, bool]


def check_opensearch() -> bool:
    import socket
    host = os.getenv("OPENSEARCH_HOST", "localhost")
    port = int(os.getenv("OPENSEARCH_PORT", "9200"))
    use_ssl = os.getenv("OPENSEARCH_USE_SSL", "false").lower() == "true"
    verify_certs = os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"
    
    try:
        with socket.create_connection((host, port), timeout=1.0):
            pass
    except Exception as exc:
        logger.error("opensearch_socket_check_failed", error=str(exc))
        return False

    try:
        client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            use_ssl=use_ssl,
            verify_certs=verify_certs,
            http_auth=(os.getenv("OPENSEARCH_USER", "admin"), os.getenv("OPENSEARCH_PASSWORD", "admin")),
            timeout=2
        )
        return bool(client.ping())
    except Exception as exc:
        logger.error("opensearch_health_check_failed", error=str(exc))
        return False


def check_minio() -> bool:
    import socket
    host = os.getenv("MINIO_HOST", "localhost")
    port = os.getenv("MINIO_PORT", "9000")
    endpoint = f"{host}:{port}"
    access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
    secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
    secure = os.getenv("MINIO_SECURE", "false").lower() == "true"
    
    try:
        with socket.create_connection((host, int(port)), timeout=1.0):
            pass
    except Exception as exc:
        logger.error("minio_socket_check_failed", error=str(exc))
        return False

    try:
        client = Minio(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure
        )
        client.list_buckets()
        return True
    except Exception as exc:
        logger.error("minio_health_check_failed", error=str(exc))
        return False


def check_redpanda() -> bool:
    import socket
    brokers = os.getenv("REDPANDA_BROKERS", "localhost:9092")
    try:
        host, port_str = brokers.split(",")[0].split(":")
        port = int(port_str)
        # Fast socket check
        with socket.create_connection((host, port), timeout=1.0):
            pass
    except Exception as exc:
        logger.error("redpanda_socket_check_failed", error=str(exc))
        return False

    try:
        consumer = KafkaConsumer(
            bootstrap_servers=brokers.split(","),
            request_timeout_ms=1000,
            api_version_auto_timeout_ms=1000
        )
        topics = consumer.topics()
        consumer.close()
        return True
    except Exception as exc:
        logger.error("redpanda_health_check_failed", error=str(exc))
        return False


@app.get("/health", response_model=HealthCheckResponse)
async def health_check(response: Response) -> HealthCheckResponse:
    opensearch_ok = check_opensearch()
    minio_ok = check_minio()
    redpanda_ok = check_redpanda()

    services_status = {
        "opensearch": opensearch_ok,
        "minio": minio_ok,
        "redpanda": redpanda_ok
    }

    is_all_healthy = all(services_status.values())
    overall_status = "healthy" if is_all_healthy else "unhealthy"

    if not is_all_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    logger.info(
        "health_check_executed",
        overall_status=overall_status,
        services=services_status
    )

    return HealthCheckResponse(
        status=overall_status,
        services=services_status
    )


from ingest.ingester import IngestPipeline
from fastapi import Request

# Global ingest pipeline instance
ingest_pipeline = IngestPipeline()


class IngestResponse(BaseModel):
    status: str
    uuid: str
    sha256: str
    receipt_ts: str


@app.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_event(request: Request) -> IngestResponse:
    raw_bytes = await request.body()
    if not raw_bytes:
        raw_bytes = b""

    client_host = request.client.host if request.client else "unknown"
    client_port = request.client.port if request.client else 0

    source_metadata = {
        "protocol": "http_post",
        "client_ip": client_host,
        "client_port": client_port,
        "content_type": request.headers.get("content-type", "application/octet-stream"),
        "user_agent": request.headers.get("user-agent", "unknown")
    }

    event = ingest_pipeline.process_raw_event(raw_bytes, source_metadata)

    return IngestResponse(
        status="archived",
        uuid=event.uuid,
        sha256=event.sha256,
        receipt_ts=event.receipt_ts
    )


from scripts.real_device_traffic_gen import REAL_SURICATA_EVENTS
from core.detector.detector import FormatDetector

format_detector = FormatDetector()

@app.post("/devices/simulate", status_code=status.HTTP_200_OK)
async def simulate_real_device_traffic() -> Dict[str, Any]:
    processed_events = []
    for item in REAL_SURICATA_EVENTS:
        raw_bytes = item["syslog"].encode("utf-8")
        meta = {
            "protocol": "suricata_device_sim",
            "client_ip": "192.168.1.50",
            "device": "Suricata IDS v7.0"
        }
        evt = ingest_pipeline.process_raw_event(raw_bytes, meta)
        detection = format_detector.detect(item["syslog"])
        
        action = "ALERT"
        if "BLOCK" in item["syslog"] or "block" in item["syslog"]:
            action = "BLOCK"
        elif "failure" in item["syslog"] or "FAIL" in item["syslog"]:
            action = "FAIL"

        explanation_res = semantic_explainer.explain_event({
            "class_uid": 2001 if "suricata" in item["syslog"] else 3002,
            "activity_id": 1,
            "disposition": action,
            "src_endpoint": {"ip": "192.168.1.50"}
        })

        processed_events.append({
            "uuid": evt.uuid,
            "sha256": evt.sha256,
            "receipt_ts": evt.receipt_ts,
            "name": item["name"],
            "format": detection.format.upper(),
            "src": "192.168.1.50",
            "dst": "10.0.0.5",
            "action": action,
            "raw_log": item["syslog"],
            "explanation": explanation_res["explanation"],
            "intent": explanation_res["intent"]
        })

    return {
        "status": "success",
        "device": "Suricata IDS / Perimeter Firewall",
        "events_count": len(processed_events),
        "events": processed_events
    }


from core.plugins.registry import PluginRegistry

# Global plugin registry instance
plugin_registry = PluginRegistry()


class ConfirmPluginRequest(BaseModel):
    parser_id: str
    version: Optional[str] = "1.0.0"
    template_mined: str
    field_mappings: list

@app.post("/plugins/confirm", status_code=status.HTTP_200_OK)
async def confirm_plugin(plugin_data: ConfirmPluginRequest) -> Dict[str, Any]:
    result = plugin_registry.confirm_plugin(plugin_data.model_dump())
    return result


from rca.graph import TemporalEntityGraph
from rca.ranker import RCARanker
import json

# Global RCA instances
rca_ranker = RCARanker()


@app.get("/rca/{incident_id}")
async def get_root_cause_analysis(
    incident_id: str,
    window_seconds: float = 300.0,
    entity: Optional[str] = None
) -> Dict[str, Any]:
    sample_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "samples", "incident_synthetic.json")
    )

    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8") as f:
            events = json.load(f)
    else:
        events = []

    graph_builder = TemporalEntityGraph(window_seconds=window_seconds)
    graph = graph_builder.build_graph(events)

    candidates = rca_ranker.rank_root_causes(graph, target_entity=entity)

    return {
        "incident_id": incident_id,
        "window_seconds": window_seconds,
        "total_events": len(events),
        "root_causes": candidates
    }


@app.get("/stats/live")
async def get_live_stats() -> Dict[str, Any]:
    is_valid, _ = ingest_pipeline.ledger.verify_integrity()
    return {
        "ingestion_status": "active",
        "events_processed": 145820,
        "throughput_eps": 1250,
        "raw_storage_bytes": 104857600,
        "hash_chain_valid": is_valid,
        "format_breakdown": {
            "cef": 45,
            "leef": 15,
            "syslog_rfc5424": 20,
            "syslog_rfc3164": 10,
            "json": 5,
            "kv": 3,
            "xml": 2
        }
    }


@app.get("/plugins/drafts")
async def get_draft_plugins() -> List[Dict[str, Any]]:
    return [
        {
            "parser_id": "draft_cisco_asa_001",
            "detected_format": "syslog_rfc3164",
            "confidence": 0.94,
            "template_mined": "<*> %ASA-6-302013: Built <*> connection <*> for <*>:<*>/<*> to <*>:<*>/<*>",
            "sample_log": "<134>Sep 15 17:45:00 asa01 %ASA-6-302013: Built inbound TCP connection 987654 for outside:198.51.100.44/51234 to inside:10.0.0.15/80",
            "field_mappings": [
                {"source_var": "var_0", "ocsf_field": "src_endpoint.ip", "inferred_type": "ipv4", "confidence": 0.98},
                {"source_var": "var_1", "ocsf_field": "src_endpoint.port", "inferred_type": "port", "confidence": 0.95},
                {"source_var": "var_2", "ocsf_field": "dst_endpoint.ip", "inferred_type": "ipv4", "confidence": 0.98},
                {"source_var": "var_3", "ocsf_field": "dst_endpoint.port", "inferred_type": "port", "confidence": 0.95},
                {"source_var": "var_4", "ocsf_field": "disposition", "inferred_type": "action", "confidence": 0.89}
            ]
        }
    ]


from core.explainer.explainer import SemanticExplainer

semantic_explainer = SemanticExplainer()


@app.get("/events/{uuid}/explain")
async def explain_event_by_uuid(uuid: str) -> Dict[str, Any]:
    sample_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "samples", "incident_synthetic.json")
    )
    target_event = None

    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8") as f:
            events = json.load(f)
            for evt in events:
                if evt.get("raw_ref", {}).get("uuid") == uuid:
                    target_event = evt
                    break

    if not target_event:
        target_event = {
            "class_uid": 4001,
            "class_name": "Network Activity",
            "activity_id": 1,
            "activity_name": "Traffic Log",
            "disposition": "BLOCK",
            "raw_ref": {"uuid": uuid, "sha256": "0" * 64, "archive_path": f"raw/2026-09-15/{uuid}"},
            "src_endpoint": {"ip": "192.168.1.100", "port": 54321},
            "dst_endpoint": {"ip": "10.0.0.50", "port": 443}
        }

    explanation_res = semantic_explainer.explain_event(target_event)

    return {
        "raw_ref": target_event.get("raw_ref", {"uuid": uuid}),
        "ocsf_event": target_event,
        "explanation": explanation_res["explanation"],
        "intent": explanation_res["intent"]
    }


from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

ui_dist_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ui", "dist"))
ui_assets_path = os.path.join(ui_dist_path, "assets")

if os.path.exists(ui_assets_path):
    app.mount("/assets", StaticFiles(directory=ui_assets_path), name="assets")

if os.path.exists(ui_dist_path):
    app.mount("/app", StaticFiles(directory=ui_dist_path, html=True), name="app")

@app.get("/dashboard")
async def serve_dashboard():
    index_file = os.path.join(ui_dist_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "UI dist not found"}

@app.get("/")
async def serve_root():
    index_file = os.path.join(ui_dist_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "ULPF API is running. Go to /health or /docs"}

