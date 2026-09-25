"""
Per-entity, per-window features: what one source address, one user or one device did in each
5-minute window, as numbers a model or a baseline can use.

Each row is computed from the events inside its own window, plus, for "new destination", the
destinations the same entity reached in earlier windows. Nothing from a later window is used, so a
feature row is the same whether it is computed live, as its window closes, or a month later from
the archive, and a model trained on these rows cannot learn from the future.

Values follow the data contract (rows.py): when no event in a window reported bytes, the window's
bytes are null, not 0. Detection findings TRACELOG's own detector wrote are left out, so the detector
never learns from its own output.
"""
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import numpy as np
import pandas as pd

from backend.services import jsonio
from backend.services.ml.rows import NAMES, ml_row
from backend.services.normalization.ocsf_export import to_ocsf

WINDOW_MINUTES = 5
DETECTOR_PARSER = "tracelog_baseline"     # the vendor pack that reads the detector's own findings

# the entity each kind of row describes, and the event column that names it
ENTITY_TYPES = {"src_ip": "src_ip", "user": "user_name", "device": "device"}

# columns the features need (the full contract minus the whole-event JSON)
EVENT_COLUMNS = [n for n in NAMES if n != "ocsf"]

FEATURES = [
    "events", "denied", "deny_ratio", "distinct_dst_ips", "distinct_dst_ports", "distinct_src_ips",
    "new_dst_ips", "new_dst_share", "bytes_out", "bytes_in", "auth_failures", "auth_successes", "findings",
    "max_severity_id", "unverified_events", "received_time_events", "hour_of_day", "day_of_week",
]
FEATURE_COLUMNS = (["entity_type", "entity", "window_start", "window_start_ms", "window_end_ms",
                    "history_windows"] + FEATURES + ["first_sequence", "last_sequence"])


def events_frame(rows: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    """Contract rows as a DataFrame with the columns the features read (missing ones as null)."""
    df = pd.DataFrame(list(rows))
    for col in EVENT_COLUMNS:
        if col not in df.columns:
            df[col] = None
    df = df[EVENT_COLUMNS]
    for col in ("time", "class_uid", "status_id", "action_id", "disposition_id", "dst_port", "severity_id",
                "bytes_in", "bytes_out", "sequence_num"):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df["fields_verified"] = df["fields_verified"].fillna(False).astype(bool)
    # a device is known by the hostname in its log; behind no hostname, by the address it sent from
    df["device"] = df["device_hostname"].where(df["device_hostname"].notna(), df["sender_ip"])
    return df


def events_from_db(database=None, since_ms: Optional[int] = None, until_ms: Optional[int] = None,
                   include_detector: bool = False) -> pd.DataFrame:
    """Current events (not superseded by a re-parse) with event time in [since_ms, until_ms)."""
    if database is None:
        from backend.services.storage import db as db_module
        database = db_module.db
    sql = "SELECT normalized_json FROM normalized_events WHERE superseded_by IS NULL"
    args: List[Any] = []
    if since_ms is not None:
        sql += " AND time_epoch_ms >= ?"
        args.append(int(since_ms))
    if until_ms is not None:
        sql += " AND time_epoch_ms < ?"
        args.append(int(until_ms))
    if not include_detector:
        sql += " AND (parser_pack IS NULL OR parser_pack != ?)"
        args.append(DETECTOR_PARSER)
    sql += " ORDER BY time_epoch_ms, sequence_num"
    with database.get_connection() as conn:
        rows = conn.execute(sql, args).fetchall()
    return events_frame(ml_row(to_ocsf(jsonio.loads(r["normalized_json"]), include_raw=False), include_ocsf=False)
                        for r in rows)


def events_from_parquet(root, include_detector: bool = False) -> pd.DataFrame:
    """Events from the Parquet output's files (either layout). Files written before a column existed
    simply have it null."""
    import pyarrow.parquet as pq

    tables = []
    for path in sorted(Path(root).rglob("*.parquet")):
        names = set(pq.read_schema(path).names)
        tables.append(pq.read_table(path, columns=[c for c in EVENT_COLUMNS if c in names]).to_pandas())
    df = events_frame(pd.concat(tables, ignore_index=True).to_dict("records") if tables else [])
    if not include_detector:
        df = df[df["parser"] != DETECTOR_PARSER]
    return df.sort_values(["time", "sequence_num"], kind="stable").reset_index(drop=True)


def _sum_or_null(grouped) -> pd.Series:
    """Per-window sums, null where no event in the window reported the value: "the device did not
    say", not "zero bytes"."""
    return grouped.sum().where(grouped.count() > 0)


def window_features(events: pd.DataFrame, entity_type: str, window_minutes: int = WINDOW_MINUTES) -> pd.DataFrame:
    """One row per (entity, window) in which the entity appears; FEATURE_COLUMNS, ordered by window."""
    column = ENTITY_TYPES[entity_type]
    width = window_minutes * 60 * 1000
    d = events[events[column].notna() & events["time"].notna()].copy()
    if d.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS)
    d["entity"] = d[column].astype(str)
    d["window_start_ms"] = (d["time"].astype("int64") // width) * width
    d["_denied"] = d["disposition_id"].isin([2, 6]) | (d["action_id"] == 2)
    auth = d["class_uid"] == 3002
    d["_auth_fail"] = auth & (d["status_id"] == 2)
    d["_auth_ok"] = auth & (d["status_id"] == 1)
    d["_finding"] = d["class_uid"] == 2004
    d["_unverified"] = ~d["fields_verified"]
    d["_received"] = d["time_source"] == "received"
    # a destination is new in the first window the entity reached it; earlier windows only
    d["_dst"] = d["dst_ip"].where(d["dst_ip"].notna(), d["dst_hostname"])
    first_seen = d[d["_dst"].notna()].groupby(["entity", "_dst"])["window_start_ms"].min()
    new = first_seen.reset_index().groupby(["entity", "window_start_ms"]).size().rename("new_dst_ips")

    g = d.groupby(["entity", "window_start_ms"], sort=True)
    out = pd.DataFrame({
        "events": g.size(),
        "denied": g["_denied"].sum(),
        "distinct_dst_ips": g["_dst"].nunique(),
        "distinct_dst_ports": g["dst_port"].nunique(),
        "distinct_src_ips": g["src_ip"].nunique(),
        "bytes_out": _sum_or_null(g["bytes_out"]),
        "bytes_in": _sum_or_null(g["bytes_in"]),
        "auth_failures": g["_auth_fail"].sum(),
        "auth_successes": g["_auth_ok"].sum(),
        "findings": g["_finding"].sum(),
        "max_severity_id": g["severity_id"].max(),
        "unverified_events": g["_unverified"].sum(),
        "received_time_events": g["_received"].sum(),
        "first_sequence": g["sequence_num"].min(),
        "last_sequence": g["sequence_num"].max(),
    })
    out = out.join(new).reset_index()
    out["new_dst_ips"] = out["new_dst_ips"].fillna(0).astype("int64")
    out["deny_ratio"] = out["denied"] / out["events"]
    out["new_dst_share"] = np.where(out["distinct_dst_ips"] > 0,
                                    out["new_dst_ips"] / out["distinct_dst_ips"].where(out["distinct_dst_ips"] > 0),
                                    np.nan)
    out["history_windows"] = out.groupby("entity").cumcount()   # earlier windows in which it was seen
    start = pd.to_datetime(out["window_start_ms"], unit="ms", utc=True)
    out["window_start"] = start.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    out["window_end_ms"] = out["window_start_ms"] + width
    out["hour_of_day"] = start.dt.hour
    out["day_of_week"] = start.dt.dayofweek
    out["entity_type"] = entity_type
    for col in ("events", "denied", "distinct_dst_ips", "distinct_dst_ports", "distinct_src_ips", "auth_failures",
                "auth_successes", "findings", "unverified_events", "received_time_events", "history_windows"):
        out[col] = out[col].astype("int64")
    return out[FEATURE_COLUMNS].sort_values(["window_start_ms", "entity"], kind="stable").reset_index(drop=True)


def all_features(events: pd.DataFrame, window_minutes: int = WINDOW_MINUTES,
                 entity_types: Iterable[str] = tuple(ENTITY_TYPES)) -> pd.DataFrame:
    frames = [window_features(events, t, window_minutes) for t in entity_types]
    frames = [f for f in frames if not f.empty]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=FEATURE_COLUMNS)
