import requests
import json
import logging
from typing import Dict, Any, List, Optional
from backend.config import settings

logger = logging.getLogger("ulpf.client")

BASE_URL = f"http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}{settings.API_PREFIX}"

class APIClient:
    """
    HTTP client for interacting with the ULPF FastAPI backend.
    Includes transparent local fallback to Python services if the standalone
    FastAPI daemon is unreachable.
    """

    @classmethod
    def is_backend_online(cls) -> bool:
        try:
            r = requests.get(f"http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}/health", timeout=1.5)
            return r.status_code == 200
        except Exception:
            return False

    @classmethod
    def get_overview(cls) -> Dict[str, Any]:
        try:
            r = requests.get(f"{BASE_URL}/analytics/overview", timeout=3.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        # Fallback to service directly
        from backend.api.analytics import get_overview_kpis
        return get_overview_kpis()

    @classmethod
    def seed_samples(cls) -> Dict[str, Any]:
        try:
            r = requests.post(f"{BASE_URL}/ingest/seed-samples", timeout=5.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.ingestion import seed_sample_datasets
        return seed_sample_datasets()

    @classmethod
    def list_sources(cls) -> List[Dict[str, Any]]:
        try:
            r = requests.get(f"{BASE_URL}/sources", timeout=3.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.sources import list_sources
        return [s.model_dump() for s in list_sources()]

    @classmethod
    def create_source(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            r = requests.post(f"{BASE_URL}/sources", json=data, timeout=3.0)
            if r.status_code == 201:
                return r.json()
        except Exception:
            pass
        from backend.api.sources import create_source
        from backend.models.source import SourceCreate
        return create_source(SourceCreate(**data)).model_dump()

    @classmethod
    def ingest_single(cls, text: str, source_id: str, vendor: str = "Generic", product: str = "Device") -> Dict[str, Any]:
        try:
            r = requests.post(
                f"{BASE_URL}/ingest/single",
                json={"raw_text": text, "source_id": source_id, "source_vendor": vendor, "source_product": product},
                timeout=3.0
            )
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.services.ingestion.pipeline import IngestionPipeline
        return IngestionPipeline.ingest_single_log(text, source_id, vendor, product)

    @classmethod
    def list_events(cls, search: str = None, source_id: str = None, severity: str = None, class_name: str = None, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        params = {"limit": limit, "offset": offset}
        if search: params["search"] = search
        if source_id: params["source_id"] = source_id
        if severity: params["severity"] = severity
        if class_name: params["class_name"] = class_name

        try:
            r = requests.get(f"{BASE_URL}/events", params=params, timeout=4.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.events import list_events
        return list_events(search=search, source_id=source_id, severity=severity, class_name=class_name, limit=limit, offset=offset)

    @classmethod
    def get_event_detail(cls, event_id: str) -> Dict[str, Any]:
        try:
            r = requests.get(f"{BASE_URL}/events/{event_id}", timeout=3.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.events import get_event_detail
        return get_event_detail(event_id)

    @classmethod
    def list_parsers(cls) -> List[Dict[str, Any]]:
        try:
            r = requests.get(f"{BASE_URL}/parsers", timeout=3.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.parsers import list_parsers
        return [p.model_dump() for p in list_parsers()]

    @classmethod
    def generate_parser(cls, name: str, vendor: str, product: str, sample_logs: List[str], target_class: int = 4001) -> Dict[str, Any]:
        payload = {
            "name": name, "vendor": vendor, "product": product,
            "target_ocsf_class": target_class, "sample_logs": sample_logs
        }
        try:
            r = requests.post(f"{BASE_URL}/parsers/generate", json=payload, timeout=4.0)
            if r.status_code == 201:
                return r.json()
        except Exception:
            pass
        from backend.api.parsers import generate_parser, GenerateParserRequest
        return generate_parser(GenerateParserRequest(**payload)).model_dump()

    @classmethod
    def test_parser(cls, parser_id: str, sample_logs: List[str]) -> Dict[str, Any]:
        try:
            r = requests.post(f"{BASE_URL}/parsers/{parser_id}/test", json={"sample_logs": sample_logs}, timeout=4.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.parsers import test_parser, TestParserRequest
        return test_parser(parser_id, TestParserRequest(sample_logs=sample_logs)).model_dump()

    @classmethod
    def approve_parser(cls, parser_id: str) -> Dict[str, Any]:
        try:
            r = requests.post(f"{BASE_URL}/parsers/{parser_id}/approve", timeout=3.0)
            if r.status_code == 200:
                return r.json()
            return {"error": r.json().get("detail", "Approval failed")}
        except Exception:
            pass
        try:
            from backend.api.parsers import approve_parser
            return approve_parser(parser_id).model_dump()
        except Exception as e:
            return {"error": str(e)}

    @classmethod
    def reject_parser(cls, parser_id: str) -> Dict[str, Any]:
        try:
            r = requests.post(f"{BASE_URL}/parsers/{parser_id}/reject", timeout=3.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.parsers import reject_parser
        return reject_parser(parser_id).model_dump()

    @classmethod
    def verify_integrity(cls) -> Dict[str, Any]:
        try:
            r = requests.get(f"{BASE_URL}/integrity/verify", timeout=5.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.integrity import verify_hash_chain
        return verify_hash_chain().model_dump()

    @classmethod
    def get_ledger(cls, limit: int = 50) -> List[Dict[str, Any]]:
        try:
            r = requests.get(f"{BASE_URL}/integrity/ledger", params={"limit": limit}, timeout=3.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.integrity import get_ledger
        return get_ledger(limit=limit)

    @classmethod
    def simulate_tamper(cls, sequence_num: int, field: str = "disposition", value: str = "tampered_blocked") -> Dict[str, Any]:
        payload = {"sequence_num": sequence_num, "tamper_field": field, "new_value": value}
        try:
            r = requests.post(f"{BASE_URL}/integrity/tamper", json=payload, timeout=3.0)
            if r.status_code == 200:
                return r.json()
            return {"error": r.json().get("detail", "Tamper failed")}
        except Exception:
            pass
        try:
            from backend.api.integrity import simulate_tampering
            from backend.models.integrity import TamperRecordRequest
            return simulate_tampering(TamperRecordRequest(**payload)).model_dump()
        except Exception as e:
            return {"error": str(e)}

    @classmethod
    def restore_record(cls, sequence_num: int) -> Dict[str, Any]:
        payload = {"sequence_num": sequence_num}
        try:
            r = requests.post(f"{BASE_URL}/integrity/restore", json=payload, timeout=3.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.integrity import restore_tampered_record
        from backend.api.integrity import RestoreRecordRequest
        return restore_tampered_record(RestoreRecordRequest(**payload))

    @classmethod
    def run_correlation(cls, pivot_ip: Optional[str] = None) -> Dict[str, Any]:
        payload = {"pivot_ip": pivot_ip, "time_window_minutes": 60}
        try:
            r = requests.post(f"{BASE_URL}/correlation/run", json=payload, timeout=5.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.correlation import run_rca, RunCorrelationRequest
        return run_rca(RunCorrelationRequest(**payload)).model_dump()
