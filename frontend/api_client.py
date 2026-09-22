import requests
import json
import logging
from typing import Dict, Any, List, Optional
from backend.config import settings

logger = logging.getLogger("ulpf.client")

BASE_URL = f"http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}{settings.API_PREFIX}"

class APIClient:
    """
    HTTP client for the TRACELOG API.
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
    def get_unparsed(cls, limit: int = 5) -> Dict[str, Any]:
        try:
            r = requests.get(f"{BASE_URL}/analytics/unparsed", params={"limit": limit}, timeout=3.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        from backend.api.analytics import unparsed_lines
        return unparsed_lines(limit)

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
        return list_events(search=search, source_id=source_id, severity=severity, class_name=class_name, ip=None,
                           limit=limit, offset=offset, include_superseded=False)

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

    # ---- connectors (live only: inputs and outputs run inside the API server) ----------------
    @classmethod
    def get_connectors(cls) -> Optional[Dict[str, Any]]:
        """Live input/output status from the running server, or None when it is not reachable."""
        try:
            r = requests.get(f"{BASE_URL}/connectors", timeout=3.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    @classmethod
    def test_output(cls, name: str) -> Dict[str, Any]:
        try:
            r = requests.post(f"{BASE_URL}/connectors/outputs/{name}/test", timeout=20.0)
            return r.json() if r.headers.get("content-type", "").startswith("application/json") else \
                {"ok": False, "detail": r.text[:300]}
        except Exception as exc:
            return {"ok": False, "detail": f"API server not reachable: {exc}"}

    @classmethod
    def get_dead_letters(cls) -> Optional[List[Dict[str, Any]]]:
        try:
            r = requests.get(f"{BASE_URL}/connectors/dead-letters", timeout=5.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    @classmethod
    def dead_letter_entries(cls, name: str, limit: int = 10) -> Dict[str, Any]:
        try:
            r = requests.get(f"{BASE_URL}/connectors/dead-letters/{name}", params={"limit": limit}, timeout=5.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return {"summary": {}, "entries": []}

    @classmethod
    def replay_dead_letters(cls, name: str, to: Optional[str] = None, kinds: Optional[List[str]] = None,
                            limit: Optional[int] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {"wait": 60}
        if to and to != name:
            params["to"] = to
        if kinds:
            params["kinds"] = ",".join(kinds)
        if limit:
            params["limit"] = limit
        try:
            r = requests.post(f"{BASE_URL}/connectors/dead-letters/{name}/replay", params=params, timeout=70.0)
            body = r.json()
            return body if r.status_code == 200 else {"state": "error", "error": body.get("detail", r.text[:300])}
        except Exception as exc:
            return {"state": "error", "error": f"API server not reachable: {exc}"}

    # ---- reconciliation and audit report ----------------------------------------------------
    @classmethod
    def get_reconciliation(cls) -> Optional[Dict[str, Any]]:
        try:
            r = requests.get(f"{BASE_URL}/audit/reconcile", timeout=60.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    @classmethod
    def get_audit_report(cls, fmt: str = "pdf") -> Dict[str, Any]:
        """Returns {"ok", "data" (bytes), "filename", "error"}."""
        try:
            r = requests.get(f"{BASE_URL}/audit/report.{fmt}", timeout=120.0)
            if r.status_code != 200:
                detail = r.json().get("detail") if r.headers.get("content-type", "").startswith("application/json") \
                    else r.text[:300]
                return {"ok": False, "error": detail}
            cd = r.headers.get("content-disposition", "")
            name = cd.split("filename=")[-1].strip('"') if "filename=" in cd else f"tracelog-audit.{fmt}"
            return {"ok": True, "data": r.content, "filename": name}
        except Exception as exc:
            return {"ok": False, "error": f"API server not reachable: {exc}"}

    # ---- new log formats and learned parsers ------------------------------------------------
    # Served by the API when it runs; otherwise the same services are called in-process (they only need the DB).
    @classmethod
    def _formats_call(cls, method: str, path: str, local, json_body: Optional[Dict[str, Any]] = None,
                      params: Optional[Dict[str, Any]] = None, timeout: float = 30.0) -> Any:
        try:
            r = requests.request(method, f"{BASE_URL}/formats{path}", json=json_body, params=params, timeout=timeout)
        except Exception:
            from backend.services.parser_generation.workflow import WorkflowError
            try:
                return local()
            except WorkflowError as exc:
                return {"error": str(exc), **exc.detail}
            except ValueError as exc:
                return {"error": str(exc)}
        if r.status_code == 200:
            return r.json()
        try:
            detail = r.json().get("detail")
        except Exception:
            detail = r.text[:300]
        if isinstance(detail, dict):
            return {"error": detail.get("message", str(detail)), **detail}
        return {"error": detail or f"HTTP {r.status_code}"}

    @classmethod
    def list_formats(cls, status: Optional[str] = None) -> List[Dict[str, Any]]:
        def local():
            from backend.services.parsing.formats import list_formats
            from backend.services.storage import db as db_module
            with db_module.db.get_connection() as conn:
                return list_formats(conn, status)
        out = cls._formats_call("GET", "", local, params={"status": status} if status else None, timeout=5.0)
        return out if isinstance(out, list) else []

    @classmethod
    def format_detail(cls, format_id: str) -> Dict[str, Any]:
        from backend.services.parser_generation import workflow
        return cls._formats_call("GET", f"/{format_id}", lambda: workflow.format_detail(format_id))

    @classmethod
    def learn_format(cls, format_id: str, vendor: str = "", product: str = "", name: str = "") -> Dict[str, Any]:
        from backend.services.parser_generation import workflow
        body = {"vendor": vendor or None, "product": product or None, "name": name or None}
        return cls._formats_call("POST", f"/{format_id}/learn", lambda: workflow.learn_format(format_id, **body), body,
                                 timeout=120.0)

    @classmethod
    def edit_learned(cls, parser_id: str, roles: Dict[str, Optional[str]], confirmed: List[str], reviewer: str,
                     vendor: str = "", product: str = "", name: str = "") -> Dict[str, Any]:
        from backend.services.parser_generation import workflow
        body = {"roles": roles, "confirmed": confirmed, "reviewer": reviewer or "reviewer",
                "vendor": vendor or None, "product": product or None, "name": name or None}
        return cls._formats_call("PUT", f"/parsers/{parser_id}", lambda: workflow.edit(
            parser_id, roles, confirmed, reviewer or "reviewer", name or None, vendor or None, product or None), body,
            timeout=120.0)

    @classmethod
    def approve_learned(cls, parser_id: str, approved_by: str, confirmed: List[str]) -> Dict[str, Any]:
        from backend.services.parser_generation import workflow
        body = {"approved_by": approved_by, "confirmed": confirmed}
        return cls._formats_call("POST", f"/parsers/{parser_id}/approve",
                                 lambda: workflow.approve(parser_id, approved_by, confirmed), body, timeout=120.0)

    @classmethod
    def reject_learned(cls, parser_id: str) -> Dict[str, Any]:
        from backend.services.parser_generation import workflow
        return cls._formats_call("POST", f"/parsers/{parser_id}/reject", lambda: workflow.reject(parser_id))

    @classmethod
    def ignore_format(cls, format_id: str, undo: bool = False) -> Dict[str, Any]:
        from backend.services.parser_generation import workflow
        return cls._formats_call("POST", f"/{format_id}/ignore", lambda: workflow.set_ignored(format_id, not undo),
                                 params={"undo": str(undo).lower()})

    @classmethod
    def reparse_learned(cls, parser_id: str) -> Dict[str, Any]:
        from backend.services.parser_generation.reparse import reparse_history
        return cls._formats_call("POST", f"/parsers/{parser_id}/reparse", lambda: reparse_history(parser_id), {},
                                 timeout=600.0)
