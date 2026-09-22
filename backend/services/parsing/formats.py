"""
Registry of log formats no parser pack knows.

Every line the generic parser (or a learned parser) handles carries its format id: a hash
of the line's structure, never its values (see inference.fingerprint). The registry counts
lines per format, remembers which devices send it and when it was first and last seen,
and keeps up to SAMPLE_CAP sample lines. Parser Studio lists these formats as "New log
formats" and learns a parser for one from its samples.

Free-text formats that differ in exactly one word (a user name, a status word such as OK
or NODATA) are one format: the later id becomes an alias of the earlier one and that word
becomes a wildcard <*> in the template, as template miners such as Drain do. Words that
say which side an address is on (from, to, src, dst, ...) never become wildcards.

A format whose lines came from a vendor pack that produced impossible values is marked
with drift_from = that pack: the device's format changed (a firmware update, usually).
"""
import json
import logging
import threading
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.services.parsing.inference import DST_WORDS, SRC_WORDS

logger = logging.getLogger("tracelog.formats")

SAMPLE_CAP = 200
MAX_SOURCES = 20
_NO_WILDCARD = SRC_WORDS | DST_WORDS | {"port", "user", "from", "to", "by", "for", "via", "on"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _wordish(tok: str) -> bool:
    low = tok.lower().strip(",.:;()[]=")
    return "<" not in tok and bool(low) and low not in _NO_WILDCARD


class FormatRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._db = None
        self._alias: Dict[str, str] = {}
        self._known: set = set()
        self._text: Dict[Tuple[str, int], Dict[str, List[str]]] = {}
        self._templates: Dict[str, List[str]] = {}   # text formats: current template tokens (with wildcards)

    def _ensure(self, conn) -> None:
        from backend.services.storage import db as db_module
        if self._db is db_module.db:
            return
        self._alias = {r[0]: r[1] for r in conn.execute("SELECT alias, format_id FROM log_format_aliases")}
        self._known, self._text, self._templates = set(), {}, {}
        for r in conn.execute("SELECT format_id, kind, app, template FROM log_formats"):
            self._known.add(r[0])
            if r[1] == "text":
                toks = r[3].split(" ")
                self._text.setdefault((r[2] or "", len(toks)), {})[r[0]] = toks
                self._templates[r[0]] = toks
        self._db = db_module.db

    def resolve(self, conn, tp: Dict[str, Any]) -> str:
        """The registry's id for a parsed line's format (following aliases, merging near-identical text formats)."""
        fp = tp["format_id"]
        with self._lock:
            self._ensure(conn)
            if fp in self._alias:
                return self._alias[fp]
            if fp in self._known:
                return fp
            st = tp.get("structure") or {}
            if st.get("kind") == "text":
                toks = (tp.get("template") or "").split(" ")
                key = (st.get("app") or "", len(toks))
                group = self._text.setdefault(key, {})
                if len(toks) >= 4:
                    for fid, other in group.items():
                        diff = [i for i, (a, b) in enumerate(zip(toks, other)) if a != b and b != "<*>"]
                        if not diff or (len(diff) == 1 and _wordish(toks[diff[0]]) and _wordish(other[diff[0]])):
                            if diff:
                                other[diff[0]] = "<*>"
                                conn.execute("UPDATE log_formats SET template = ? WHERE format_id = ?",
                                             (" ".join(other), fid))
                            conn.execute("INSERT OR IGNORE INTO log_format_aliases (alias, format_id) VALUES (?, ?)",
                                         (fp, fid))
                            self._alias[fp] = fid
                            return fid
                group[fp] = toks
                self._templates[fp] = toks
            self._known.add(fp)
            return fp

    def note_batch(self, conn, items: List[Dict[str, Any]]) -> None:
        """items: {format_id (resolved), tp (tracelog_parse), raw_id, raw_text, source_name}. Same transaction as the
        events, so a line is never counted without being stored."""
        groups: Dict[str, Dict[str, Any]] = {}
        now = _now()
        for it in items:
            tp = it["tp"]
            g = groups.setdefault(it["format_id"], {"tp": tp, "n": 0, "conf": 0.0, "sources": Counter(),
                                                    "samples": [], "texts": set(), "drift": None, "parser": None})
            g["n"] += 1
            g["conf"] += float(tp.get("confidence") or 0)
            if it.get("source_name"):
                g["sources"][it["source_name"]] += 1
            if it["raw_text"] not in g["texts"]:
                g["texts"].add(it["raw_text"])
                g["samples"].append((it.get("raw_id"), it["raw_text"], it.get("source_name")))
            if tp.get("pack_drift"):
                g["drift"] = tp["pack_drift"]["pack"]
            if tp.get("parser_id"):
                g["parser"] = tp["parser_id"]
        for fid, g in groups.items():
            tp, st = g["tp"], g["tp"].get("structure") or {}
            with self._lock:
                toks = self._templates.get(fid)
            template = " ".join(toks) if toks else tp.get("template") or ""
            conn.execute(
                "INSERT INTO log_formats (format_id, kind, delimiter, app, template, size, first_seen, last_seen, "
                "count, confidence_sum, samples, sources_json, status, parser_id, drift_from) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, '{}', ?, ?, ?) ON CONFLICT(format_id) DO NOTHING",
                (fid, st.get("kind") or "text", st.get("delimiter"), st.get("app") or "", template,
                 st.get("size"), now, now, "learned" if g["parser"] else "new", g["parser"], g["drift"]))
            row = conn.execute("SELECT samples, sources_json FROM log_formats WHERE format_id = ?", (fid,)).fetchone()
            sources = Counter(json.loads(row[1] or "{}"))
            sources.update(g["sources"])
            sources = dict(sources.most_common(MAX_SOURCES))
            room = max(0, SAMPLE_CAP - (row[0] or 0))
            new_samples = g["samples"][:room]
            if new_samples:
                conn.executemany(
                    "INSERT INTO log_format_samples (format_id, raw_id, raw_text, source_name, added_at) "
                    "VALUES (?, ?, ?, ?, ?)", [(fid, rid, text, src, now) for rid, text, src in new_samples])
            conn.execute(
                "UPDATE log_formats SET count = count + ?, confidence_sum = confidence_sum + ?, last_seen = ?, "
                "samples = samples + ?, sources_json = ?, drift_from = COALESCE(?, drift_from), "
                "parser_id = COALESCE(?, parser_id), "
                "status = CASE WHEN ? IS NOT NULL AND status = 'new' THEN 'learned' ELSE status END "
                "WHERE format_id = ?",
                (g["n"], g["conf"], now, len(new_samples), json.dumps(sources), g["drift"], g["parser"], g["parser"],
                 fid))

    def forget_cache(self) -> None:
        with self._lock:
            self._db = None


registry = FormatRegistry()


def aliases_of(conn, format_id: str) -> List[str]:
    return [r[0] for r in conn.execute("SELECT alias FROM log_format_aliases WHERE format_id = ?", (format_id,))]


def format_row(row) -> Dict[str, Any]:
    d = dict(row)
    d["sources"] = json.loads(d.pop("sources_json") or "{}")
    d["avg_confidence"] = round(d.pop("confidence_sum") / d["count"], 2) if d["count"] else 0.0
    return d


def list_formats(conn, status: Optional[str] = None) -> List[Dict[str, Any]]:
    q = "SELECT * FROM log_formats"
    args: tuple = ()
    if status:
        q += " WHERE status = ?"
        args = (status,)
    return [format_row(r) for r in conn.execute(q + " ORDER BY count DESC", args)]
