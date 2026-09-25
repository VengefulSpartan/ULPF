"""
A statistical baseline over the window features: flag a window in which an entity did far more of
something than it usually does, and say exactly how far.

For each scored feature, a window's value x is compared with a history of the same feature:

  own history   the entity's earlier windows in the lookback (default 24 h), when it has at least
                MIN_OWN_HISTORY of them;
  peers         otherwise, every entity of the same kind in the lookback before this window (a
                source address seen for the first time is compared with all source addresses),
                when there are at least MIN_PEER_HISTORY of those;
  neither       the window is not scored, and is counted as such, rather than guessed about.

  robust z = (x - median) / spread,  spread = 1.4826 x MAD  (the median absolute deviation, scaled
  to match a standard deviation), or 1.2533 x the mean absolute deviation when the MAD is 0
  (Iglewicz and Hoaglin, 1993). When every earlier window had the same value, the spread is 0 and
  any increase counts as far above it.

A flag reads, for example, "62 destination addresses in 5 min; its 189 earlier windows: median 5,
highest 16, robust z 12.8". The z is printed only when it comes from the MAD: when more than half of
the history is one value (0 failed logins, usually), the fallback spread is tiny and its z is a huge
number that says less than "median 0, highest 3" does.

A feature is flagged when z >= THRESHOLD (3.5, Iglewicz and Hoaglin's cut-off for outliers) and x
exceeds the median by at least MIN_EXCESS for that feature: the smallest change worth a person's
time, so that 1 failed login where there are usually 0 is not an alert. Only increases are flagged.
The values below were fixed before the synthetic evaluation was run (docs/ML_DATA.md).

There is no probability or confidence here. A flag carries the measured value, the median and the
spread it was compared with, how many windows that history held, and the events in the window, so
whoever reads it can check it.

Each flag is written back through the one writer as a JSON line that the tracelog_baseline pack reads
into an OCSF Detection Finding: archived, hash-chained, and sent to the outputs like an IDS alert.
"""
import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

from backend.services.ml import features as feat

THRESHOLD = 3.5
MIN_OWN_HISTORY = 8          # earlier windows of the same entity
MIN_PEER_HISTORY = 30        # earlier entity-windows of the same kind
LOOKBACK_HOURS = 24
EVIDENCE_EVENTS = 50         # event ids listed in a finding; the count and sequence range cover the rest
SEVERITY = "medium"          # an anomaly is a reason to look, not a verdict: one fixed level

# feature -> smallest increase over the median worth flagging, per kind of entity
MIN_EXCESS: Dict[str, Dict[str, float]] = {
    "src_ip": {"events": 100, "denied": 20, "distinct_dst_ips": 20, "distinct_dst_ports": 15,
               "bytes_out": 50_000_000, "auth_failures": 5, "findings": 5},
    "user": {"auth_failures": 5, "distinct_src_ips": 5},
    "device": {"events": 1000, "denied": 100, "findings": 20},
}

LABELS = {
    "events": ("events", "event volume"), "denied": ("denied connections", "denied connections"),
    "distinct_dst_ips": ("destination addresses", "number of destinations"),
    "distinct_dst_ports": ("destination ports", "number of destination ports"),
    "distinct_src_ips": ("source addresses", "number of source addresses"),
    "bytes_out": ("sent", "data sent"), "auth_failures": ("failed logins", "failed logins"),
    "findings": ("IDS/IPS alerts", "IDS/IPS alerts"),
}
SUBJECT = {"src_ip": "from {}", "user": "for user {}", "device": "at device {}"}
TITLE_ORDER = ["distinct_dst_ports", "distinct_dst_ips", "bytes_out", "auth_failures", "distinct_src_ips",
               "denied", "findings", "events"]


@dataclass
class Reason:
    feature: str
    value: float
    median: float
    highest: float                   # the largest value in the history
    spread: float
    spread_from: str                 # "mad", "mean absolute deviation", or "none" (every value the same)
    robust_z: Optional[float]        # None when the spread is 0
    history: int                     # windows in the history compared with
    baseline: str                    # "own history" or "peers"
    min_excess: float

    def text(self, window_minutes: int) -> str:
        noun = LABELS[self.feature][0]
        value = _fmt(self.value, self.feature)
        whose = "its" if self.baseline == "own history" else "all peers'"
        z = f", robust z {self.robust_z:.1f}" if self.spread_from == "mad" else ""
        return (f"{value} {noun} in {window_minutes} min; {whose} {self.history} earlier windows: "
                f"median {_fmt(self.median, self.feature)}, highest {_fmt(self.highest, self.feature)}{z}")


@dataclass
class Flag:
    entity_type: str
    entity: str
    window_start_ms: int
    window_end_ms: int
    reasons: List[Reason]
    events: int = 0
    first_sequence: Optional[int] = None
    last_sequence: Optional[int] = None
    event_uids: List[str] = field(default_factory=list)

    @property
    def finding_uid(self) -> str:
        """The same entity and window always give the same id, so running the detector again over the
        same period finds the flag already written instead of writing it twice."""
        key = f"baseline|{self.entity_type}|{self.entity}|{self.window_start_ms}"
        return "baseline-" + hashlib.sha256(key.encode()).hexdigest()[:16]

    def title(self) -> str:
        names = [LABELS[r.feature][1] for r in sorted(self.reasons, key=lambda r: TITLE_ORDER.index(r.feature))]
        return f"Unusual {' and '.join(names)} {SUBJECT[self.entity_type].format(self.entity)}"

    def summary(self, window_minutes: int) -> str:
        return "; ".join(r.text(window_minutes) for r in self.reasons)

    def line(self, window_minutes: int = feat.WINDOW_MINUTES) -> str:
        """The JSON line the writer archives and the tracelog_baseline pack reads. Keys sorted and no
        spaces, so the same flag is always the same bytes, and the same SHA-256."""
        return json.dumps({
            "tracelog_detector": "baseline", "version": 1, "finding_uid": self.finding_uid,
            "time": _iso(self.window_end_ms), "window_start": _iso(self.window_start_ms),
            "window_end": _iso(self.window_end_ms), "entity_type": self.entity_type, "entity": self.entity,
            "title": self.title(), "summary": self.summary(window_minutes), "severity": SEVERITY,
            "threshold": THRESHOLD, "reasons": [_clean(asdict(r)) for r in self.reasons],
            "evidence": {"events": self.events, "first_sequence": self.first_sequence,
                         "last_sequence": self.last_sequence, "event_uids": self.event_uids},
        }, sort_keys=True, separators=(",", ":"))


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt(value: float, feature: str) -> str:
    if feature == "bytes_out":
        for unit, size in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
            if value >= size:
                return f"{value / size:.1f} {unit}"
        return f"{value:.0f} B"
    return f"{value:g}" if value != int(value) else f"{int(value)}"


def _clean(d: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in d.items():
        if isinstance(v, (float, np.floating)):
            v = None if not math.isfinite(float(v)) else round(float(v), 3)
        elif isinstance(v, np.integer):
            v = int(v)
        out[k] = v
    return out


@dataclass
class Stats:
    n: int
    median: float
    highest: float
    spread: float
    spread_from: str


def stats(history: np.ndarray) -> Stats:
    """Median, highest and spread of a history (see the module docstring for the spread)."""
    median = float(np.median(history))
    dev = np.abs(history - median)
    spread, source = 1.4826 * float(np.median(dev)), "mad"
    if spread == 0:
        spread, source = 1.2533 * float(np.mean(dev)), "mean absolute deviation"
    if spread == 0:
        source = "none"
    return Stats(len(history), median, float(np.max(history)), spread, source)


def judge(x: float, st: Stats, baseline: str, feature: str, min_excess: float) -> Optional[Reason]:
    """A Reason when x is at least min_excess above the median and THRESHOLD spreads above it."""
    if x - st.median < min_excess:
        return None
    z = None if st.spread == 0 else float((x - st.median) / st.spread)
    if z is not None and z < THRESHOLD:
        return None
    return Reason(feature, float(x), st.median, st.highest, st.spread, st.spread_from, z, st.n, baseline,
                  min_excess)


@dataclass
class Scored:
    flags: List[Flag]
    windows_scored: int              # entity-windows that had a history to compare with
    windows_without_history: int     # entity-windows that did not, so were not scored


def score(features: pd.DataFrame, entity_type: str, since_ms: Optional[int] = None,
          until_ms: Optional[int] = None, lookback_hours: float = LOOKBACK_HOURS) -> Scored:
    """Flags for the windows of one kind of entity that start in [since_ms, until_ms). History comes
    from every row in `features` before each window, so pass rows from before since_ms too."""
    f = features[features["entity_type"] == entity_type].sort_values(["window_start_ms", "entity"], kind="stable")
    f = f.reset_index(drop=True)
    thresholds = MIN_EXCESS[entity_type]
    lookback = int(lookback_hours * 3600 * 1000)
    starts = f["window_start_ms"].to_numpy(dtype="int64")
    target = np.ones(len(f), dtype=bool)
    if since_ms is not None:
        target &= starts >= since_ms
    if until_ms is not None:
        target &= starts < until_ms

    values = {name: f[name].to_numpy(dtype="float64") for name in thresholds}
    # each entity's rows in window order, and their window starts, for its own history
    by_entity: Dict[str, np.ndarray] = {e: np.sort(idx.to_numpy()) for e, idx in f.groupby("entity").groups.items()}
    entity_starts = {e: starts[rows] for e, rows in by_entity.items()}
    peers: Dict[int, Dict[str, Optional[Stats]]] = {}     # the same for every entity in a window

    def history_stats(rows: np.ndarray, name: str, minimum: int) -> Optional[Stats]:
        h = values[name][rows]
        h = h[~np.isnan(h)]                   # windows in which the device did not report the value
        return stats(h) if len(h) >= minimum else None

    flags: List[Flag] = []
    scored = unscored = 0
    for i in np.flatnonzero(target):
        t, entity = int(starts[i]), f.at[i, "entity"]
        mine, mine_starts = by_entity[entity], entity_starts[entity]
        own = mine[np.searchsorted(mine_starts, t - lookback, "left"):np.searchsorted(mine_starts, t, "left")]
        if len(own) >= MIN_OWN_HISTORY:
            baseline, rows, minimum, cache = "own history", own, MIN_OWN_HISTORY, {}
        else:
            lo, hi = int(np.searchsorted(starts, t - lookback, "left")), int(np.searchsorted(starts, t, "left"))
            if hi - lo < MIN_PEER_HISTORY:
                unscored += 1
                continue
            baseline, rows, minimum, cache = "peers", np.arange(lo, hi), MIN_PEER_HISTORY, peers.setdefault(t, {})
        scored += 1
        reasons = []
        for name, min_excess in thresholds.items():
            x = values[name][i]
            # every feature is a count or a sum, so its median is >= 0: a value below min_excess cannot
            # be min_excess above it, and its history need not be read
            if math.isnan(x) or x < min_excess:
                continue                      # (nan: the device did not report it in this window)
            if name not in cache:
                cache[name] = history_stats(rows, name, minimum)
            if cache[name] is None:
                continue                      # too few earlier windows reported it
            reason = judge(x, cache[name], baseline, name, min_excess)
            if reason:
                reasons.append(reason)
        if reasons:
            flags.append(Flag(entity_type, str(entity), t, int(f.at[i, "window_end_ms"]), reasons,
                              events=int(f.at[i, "events"]), first_sequence=_int(f.at[i, "first_sequence"]),
                              last_sequence=_int(f.at[i, "last_sequence"])))
    return Scored(flags, scored, unscored)


def _int(v: Any) -> Optional[int]:
    return None if v is None or (isinstance(v, float) and math.isnan(v)) else int(v)


def attach_evidence(flags: List[Flag], events: pd.DataFrame) -> None:
    """List the ids of the events each flag was computed from, in chain order."""
    for flag in flags:
        column = feat.ENTITY_TYPES[flag.entity_type]
        mine = events[(events[column].astype(str) == flag.entity) & (events["time"] >= flag.window_start_ms)
                      & (events["time"] < flag.window_end_ms)].sort_values("sequence_num")
        flag.event_uids = [str(u) for u in mine["event_uid"].head(EVIDENCE_EVENTS) if u is not None]


def detect(events: pd.DataFrame, since_ms: Optional[int] = None, until_ms: Optional[int] = None,
           window_minutes: int = feat.WINDOW_MINUTES, lookback_hours: float = LOOKBACK_HOURS,
           entity_types: Iterable[str] = tuple(MIN_EXCESS)) -> Scored:
    """Features, then scores, for every kind of entity; flags carry their evidence."""
    flags: List[Flag] = []
    scored = unscored = 0
    for entity_type in entity_types:
        f = feat.window_features(events, entity_type, window_minutes)
        if f.empty:
            continue
        result = score(f, entity_type, since_ms, until_ms, lookback_hours)
        flags += result.flags
        scored += result.windows_scored
        unscored += result.windows_without_history
    attach_evidence(flags, events)
    flags.sort(key=lambda fl: (fl.window_start_ms, fl.entity_type, fl.entity))
    return Scored(flags, scored, unscored)


def already_written(database, uids: List[str]) -> set:
    """The finding ids among `uids` that are already stored (so a rerun writes each flag once)."""
    if not uids:
        return set()
    with database.get_connection() as conn:
        rows = conn.execute(
            "SELECT json_extract(normalized_json, '$.finding.uid') AS uid FROM normalized_events "
            "WHERE parser_pack = ? AND superseded_by IS NULL", (feat.DETECTOR_PARSER,)).fetchall()
    stored = {r["uid"] for r in rows}
    return {u for u in uids if u in stored}


def write_findings(flags: List[Flag], database=None, window_minutes: int = feat.WINDOW_MINUTES) -> List[Any]:
    """Write each new flag through the one writer (archive, parse, OCSF, hash chain) and hand the
    stored findings to the outputs. Returns the stored events."""
    from backend.services.ingestion.pipeline import _route
    from backend.services.ingestion.stream import InboundRecord, StreamIngestor

    if database is None:
        from backend.services.storage import db as db_module
        database = db_module.db
    done = already_written(database, [fl.finding_uid for fl in flags])
    records = [InboundRecord(raw=fl.line(window_minutes).encode("utf-8"), transport="internal",
                             input_name="baseline-detector",
                             hints={"source_name": "TRACELOG baseline detector", "vendor": "TRACELOG",
                                    "product": "Baseline detector"})
               for fl in flags if fl.finding_uid not in done]
    if not records:
        return []
    stored = StreamIngestor().ingest(records)
    _route(stored)
    return stored


def run(database=None, until_ms: Optional[int] = None, score_hours: float = 1.0,
        lookback_hours: float = LOOKBACK_HOURS, window_minutes: int = feat.WINDOW_MINUTES,
        write: bool = True) -> Dict[str, Any]:
    """Score the complete windows of the last `score_hours` before `until_ms` (default: now), with
    `lookback_hours` of history before them, and write the new flags as findings."""
    width = window_minutes * 60 * 1000
    if until_ms is None:
        until_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    until_ms = (until_ms // width) * width                   # complete windows only
    since_ms = until_ms - int(score_hours * 3600 * 1000)
    events = feat.events_from_db(database, since_ms=since_ms - int(lookback_hours * 3600 * 1000),
                                 until_ms=until_ms)
    result = detect(events, since_ms, until_ms, window_minutes, lookback_hours)
    stored = write_findings(result.flags, database, window_minutes) if write else []
    return {
        "scored_from": _iso(since_ms), "scored_until": _iso(until_ms), "events_read": int(len(events)),
        "windows_scored": result.windows_scored, "windows_without_history": result.windows_without_history,
        "flags": len(result.flags), "findings_written": len(stored),
        "findings": [{"finding_uid": fl.finding_uid, "title": fl.title(), "summary": fl.summary(window_minutes),
                      "window_start": _iso(fl.window_start_ms), "entity_type": fl.entity_type,
                      "entity": fl.entity, "events": fl.events} for fl in result.flags],
    }


class Schedule:
    """Runs the detector shortly after each window closes (setting BASELINE_EVERY_MINUTES; 0 = off).

    Each run scores the last two intervals, so a window whose events arrived late is scored again;
    a flag already written is found by its id and not written twice."""
    GRACE_SECONDS = 30

    def __init__(self, every_minutes: int):
        import threading
        self.every = max(1, int(every_minutes))
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="baseline-detector", daemon=True)
        self.last: Optional[Dict[str, Any]] = None

    def start(self) -> "Schedule":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def _delay(self) -> float:
        period = self.every * 60
        now = datetime.now(timezone.utc).timestamp()
        return period - (now % period) + self.GRACE_SECONDS

    def _loop(self) -> None:
        import logging
        log = logging.getLogger("tracelog.baseline")
        while not self._stop.wait(self._delay()):
            try:
                self.last = run(score_hours=2 * self.every / 60)
                if self.last["findings_written"]:
                    log.info("baseline detector wrote %d findings", self.last["findings_written"])
            except Exception:
                log.exception("baseline detector run failed")
