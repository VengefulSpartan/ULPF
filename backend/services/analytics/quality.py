"""
Measured pipeline quality, for the dashboard: nothing here is a constant.

  parse_breakdown     how the current version of every stored event was parsed: by a vendor
                      pack, by a learned parser a person approved, by the generic parser
                      (fields only where there is evidence, marked unverified), or not at all
  ocsf_conformance    the share of the latest events whose OCSF export passes the OCSF 1.1.0
                      checks in normalization/ocsf_export.validate, with the commonest failures
  pipeline_counts     archive, events, revisions and hash-chain records, and whether they add up
"""
from collections import Counter
from typing import Any, Dict

from backend.services import jsonio
from backend.services import jsonio
from backend.services.normalization.ocsf_export import to_ocsf, validate

GENERIC, LEARNED, ERROR = "generic_inferred", "learned", "parse_error"


def _group(pack: str) -> str:
    if pack == GENERIC:
        return "generic"
    if pack and pack.startswith(LEARNED):
        return "learned"
    if pack in (ERROR, None, ""):
        return "error"
    return "pack"


def parse_breakdown(conn) -> Dict[str, Any]:
    """How the current version of every stored event was parsed, counted from the parser_pack column.

    The column is indexed, so this is an index-only scan; events written before the column existed
    (or by something that did not set it) are resolved from their raw line in a second query, which
    runs only when there are any.
    """
    rows = conn.execute("SELECT parser_pack AS pack, COUNT(*) AS n FROM normalized_events "
                        "WHERE superseded_by IS NULL GROUP BY parser_pack").fetchall()
    by_pack = {r["pack"]: r["n"] for r in rows if r["pack"]}
    if any(r["pack"] is None for r in rows):
        for r in conn.execute(
                "SELECT COALESCE(json_extract(n.unmapped_json, '$.tracelog_parse.parser_pack'), "
                "r.format_detected) AS pack, COUNT(*) AS n FROM normalized_events n "
                "JOIN raw_logs r ON r.id = n.raw_id "
                "WHERE n.superseded_by IS NULL AND n.parser_pack IS NULL GROUP BY pack").fetchall():
            pack = r["pack"] or ERROR
            by_pack[pack] = by_pack.get(pack, 0) + r["n"]

    groups = Counter()
    for pack, n in by_pack.items():
        groups[_group(pack)] += n
    total = sum(groups.values())

    def pct(k: str) -> float:
        return round(100.0 * groups[k] / total, 1) if total else 0.0

    return {"total": total, "by_parser": dict(sorted(by_pack.items(), key=lambda kv: -kv[1])),
            "vendor_pack": groups["pack"], "learned": groups["learned"], "generic": groups["generic"],
            "unparsed": groups["error"], "known_parser_pct": round(pct("pack") + pct("learned"), 1),
            "generic_pct": pct("generic"), "unparsed_pct": pct("error")}


_CHECKED: Dict[str, Dict[str, Any]] = {}   # database file -> what has already been checked


def _database_file(conn) -> str:
    row = conn.execute("PRAGMA database_list").fetchone()
    return (row[2] if row else "") or ":memory:"


def ocsf_conformance(conn, sample: int = 2000) -> Dict[str, Any]:
    """
    How many stored events pass the OCSF 1.1.0 checks in normalization/ocsf_export.validate.

    Events never change once written, so an event checked a moment ago does not need checking
    again: the first call checks the newest `sample` events, and later calls only check what
    arrived since. The dashboard therefore stays fast while the number behind it grows.
    """
    state = _CHECKED.setdefault(_database_file(conn),
                                {"after": None, "checked": 0, "valid": 0, "failures": Counter()})
    if state["after"] is None:
        rows = conn.execute("SELECT sequence_num, normalized_json FROM normalized_events "
                            "WHERE superseded_by IS NULL ORDER BY sequence_num DESC LIMIT ?",
                            (sample,)).fetchall()
    else:
        rows = conn.execute("SELECT sequence_num, normalized_json FROM normalized_events "
                            "WHERE superseded_by IS NULL AND sequence_num > ? ORDER BY sequence_num LIMIT ?",
                            (state["after"], max(sample, 20000))).fetchall()
    for r in rows:
        problems = validate(to_ocsf(jsonio.loads(r["normalized_json"])))
        if problems:
            state["failures"].update(problems)
        else:
            state["valid"] += 1
        state["checked"] += 1
        state["after"] = max(state["after"] or 0, r["sequence_num"])

    checked, valid = state["checked"], state["valid"]
    return {"checked": checked, "valid": valid,
            "valid_pct": round(100.0 * valid / checked, 1) if checked else 0.0,
            "top_failures": state["failures"].most_common(5)}


def forget_checked() -> None:
    """Drop what has been checked (tests, and a database that was replaced under us)."""
    _CHECKED.clear()


def pipeline_counts(conn) -> Dict[str, Any]:
    raw = conn.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0]
    events = conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
    chained = conn.execute("SELECT COUNT(*) FROM integrity_ledger").fetchone()[0]
    revisions = conn.execute("SELECT COUNT(*) FROM event_revisions").fetchone()[0]
    streamed = conn.execute("SELECT COUNT(*) FROM raw_logs WHERE transport IS NOT NULL").fetchone()[0]
    return {"raw_archived": raw, "events": events, "current_events": events - revisions, "revisions": revisions,
            "hash_chained": chained, "streamed": streamed,
            "consistent": raw == events - revisions and events == chained}
