"""
File outputs for data lakes and air-gapped hand-off:
- `file`: OCSF NDJSON, one file per day (path may contain strftime codes);
- `parquet`: columnar files (requires the optional `pyarrow` package), queryable with DuckDB,
  Spark, Athena or Trino, in one of two layouts:

    hive (default)    root/class_uid=4001/event_day=20260921/part-....parquet
    security_lake     root/ext/<source>/region=<region>/accountId=<id>/eventDay=20260921/
                      class_uid=4001-....parquet

  The second is the object layout Amazon Security Lake requires of a custom source: those
  three partition keys in that order, eventDay as YYYYMMDD in UTC, one OCSF event class per
  object, zstd compression, rows ordered by time, data pages under 1 MB and row groups under
  256 MB. TRACELOG writes the files; getting them into the bucket is `aws s3 sync` (or any
  copy that preserves the paths), which keeps this output usable air-gapped.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .base import DeliveryError, Sink
from .formats import ts_iso


def _event_dt(e: Dict[str, Any]) -> datetime:
    return datetime.fromtimestamp((e.get("time") or 0) / 1000.0, tz=timezone.utc)


def _ocsf_version(e: Dict[str, Any]) -> Tuple[int, ...]:
    text = str((e.get("metadata") or {}).get("version") or "0")
    try:
        return tuple(int(part) for part in text.split(".")[:2])
    except ValueError:
        return (0,)


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
    LAYOUTS = ("hive", "security_lake")
    # Security Lake's ceilings, as sizes pyarrow understands: pages under 1 MB uncompressed, and a
    # row-group row count that keeps a group far below the 256 MB compressed limit at our row width.
    DATA_PAGE_SIZE = 1024 * 1024
    ROW_GROUP_ROWS = 50_000
    MAX_OCSF_VERSION = (1, 3)   # Security Lake reads OCSF 1.3 and earlier; TRACELOG emits 1.1.0

    def validate_settings(self):
        self.s.setdefault("root", "data/lake")
        self.s.setdefault("layout", "hive")
        self.s.setdefault("compression", "zstd")
        if self.s["layout"] not in self.LAYOUTS:
            raise ValueError(f"parquet layout must be one of {', '.join(self.LAYOUTS)}")
        if self.s["layout"] == "security_lake":
            # AWS matches these against the custom source it was registered with, so a wrong or
            # invented value produces a partition Security Lake will not read. No guessing.
            if not self.s.get("region"):
                raise ValueError("parquet layout 'security_lake' needs the region the custom source "
                                 "was created in, e.g. region: ap-south-1")
            self.s.setdefault("source_name", "tracelog")
            self.s.setdefault("account_id", "external")  # AWS allows this for data from outside accounts
            if self.s["compression"] != "zstd":
                raise ValueError("Security Lake expects zstd-compressed Parquet")

    @property
    def security_lake(self) -> bool:
        return self.s["layout"] == "security_lake"

    def describe_target(self):
        if self.security_lake:
            return (f"{self.s['root']}/ext/{self.s['source_name']}/region={self.s['region']}"
                    f"/accountId={self.s['account_id']}/eventDay=*/class_uid=*.parquet")
        return f"{self.s['root']}/class_uid=*/event_day=*/*.parquet"

    def partition(self, event: Dict[str, Any]) -> Tuple[Path, int]:
        """The directory an event belongs in, and its OCSF class (one class per file, either way)."""
        class_uid = event.get("class_uid", 0)
        day = f"{_event_dt(event):%Y%m%d}"          # UTC, as both layouts require
        root = Path(self.s["root"])
        if self.security_lake:
            return (root / "ext" / str(self.s["source_name"]) / f"region={self.s['region']}"
                    / f"accountId={self.s['account_id']}" / f"eventDay={day}", class_uid)
        return root / f"class_uid={class_uid}" / f"event_day={day}", class_uid

    def file_name(self, class_uid: int) -> str:
        stamp = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:8]}"
        # the class is in the path already under the hive layout; under Security Lake's it is not,
        # and one class per object is a requirement, so the name carries it
        return f"class_uid={class_uid}-{stamp}.parquet" if self.security_lake else f"part-{stamp}.parquet"

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
        if self.security_lake and batch and _ocsf_version(batch[0]) > self.MAX_OCSF_VERSION:
            # a newer schema than Security Lake ingests: fail loudly here rather than write objects
            # into the bucket that the lake will silently refuse to read
            raise DeliveryError(f"Security Lake accepts OCSF up to "
                                f"{'.'.join(str(n) for n in self.MAX_OCSF_VERSION)}; these events say "
                                f"{(batch[0].get('metadata') or {}).get('version')}", retryable=False)
        parts: Dict[Tuple[Path, int], List[Dict[str, Any]]] = {}
        for e in batch:
            parts.setdefault(self.partition(e), []).append(self._row(e))
        for (directory, class_uid), rows in parts.items():
            directory.mkdir(parents=True, exist_ok=True)
            rows.sort(key=lambda r: (r["time"] or 0))   # ordered by time: cheaper queries, and AWS asks for it
            pq.write_table(pa.Table.from_pylist(rows), directory / self.file_name(class_uid),
                           compression=self.s["compression"], data_page_size=self.DATA_PAGE_SIZE,
                           row_group_size=self.ROW_GROUP_ROWS)
