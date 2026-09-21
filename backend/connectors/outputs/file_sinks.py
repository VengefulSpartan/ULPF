"""
File outputs for data lakes and air-gapped hand-off:
- `file`: OCSF NDJSON, one file per day (path may contain strftime codes);
- `parquet`: columnar files partitioned by class_uid and event day
  (requires the optional `pyarrow` package), queryable with DuckDB, Spark,
  Athena or Trino. Each row holds key columns plus the full OCSF event as JSON.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .base import DeliveryError, Sink
from .formats import ts_iso


def _event_dt(e: Dict[str, Any]) -> datetime:
    return datetime.fromtimestamp((e.get("time") or 0) / 1000.0, tz=timezone.utc)


class FileSink(Sink):
    type_name = "file"

    def validate_settings(self):
        self.s.setdefault("path", "data/export/ocsf-%Y-%m-%d.ndjson")

    def describe_target(self):
        return self.s["path"]

    def send(self, batch):
        by_path: Dict[str, List[str]] = {}
        for e in batch:
            path = _event_dt(e).strftime(self.s["path"])
            by_path.setdefault(path, []).append(json.dumps(e, default=str, separators=(",", ":")))
        for path, lines in by_path.items():
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")


class ParquetSink(Sink):
    type_name = "parquet"
    COLUMNS = ("time", "event_time", "class_uid", "class_name", "activity_name", "severity_id", "severity",
               "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "action", "user_name", "finding_title",
               "vendor", "product", "event_uid", "ocsf")

    def validate_settings(self):
        self.s.setdefault("root", "data/lake")

    def describe_target(self):
        return f"{self.s['root']}/class_uid=*/event_day=*/*.parquet"

    @staticmethod
    def _row(e: Dict[str, Any]) -> Dict[str, Any]:
        src, dst = e.get("src_endpoint") or {}, e.get("dst_endpoint") or {}
        prod = (e.get("metadata") or {}).get("product") or {}
        return {
            "time": e.get("time"), "event_time": ts_iso(e), "class_uid": e.get("class_uid"),
            "class_name": e.get("class_name"), "activity_name": e.get("activity_name"),
            "severity_id": e.get("severity_id"), "severity": e.get("severity"), "src_ip": src.get("ip"),
            "src_port": src.get("port"), "dst_ip": dst.get("ip"), "dst_port": dst.get("port"),
            "protocol": (e.get("connection_info") or {}).get("protocol_name"), "action": e.get("action"),
            "user_name": (e.get("user") or {}).get("name"), "finding_title": (e.get("finding_info") or {}).get("title"),
            "vendor": prod.get("vendor_name"), "product": prod.get("name"),
            "event_uid": (e.get("metadata") or {}).get("uid"), "ocsf": json.dumps(e, default=str),
        }

    def send(self, batch):
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError as exc:
            raise DeliveryError("pyarrow is not installed; use the 'file' output or install pyarrow",
                                retryable=False) from exc
        parts: Dict[Path, List[Dict[str, Any]]] = {}
        for e in batch:
            d = Path(self.s["root"]) / f"class_uid={e.get('class_uid', 0)}" / f"event_day={_event_dt(e):%Y%m%d}"
            parts.setdefault(d, []).append(self._row(e))
        for d, rows in parts.items():
            d.mkdir(parents=True, exist_ok=True)
            table = pa.Table.from_pylist(rows)
            pq.write_table(table, d / f"part-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:8]}.parquet",
                           compression=self.s.get("compression", "zstd"))
