"""
Parser Studio's workflow for new log formats:

  detected   the format registry groups lines no pack knows by structure
  learn      a parser is learned from the format's samples and tested on held-out lines
  review     a person checks each proposed field, changes any, and confirms the ones that
             rest on position alone (the parser cannot be approved until they have)
  approve    the parser goes live within seconds, for new lines of that format
  re-parse   past lines of the format are parsed again as chained revisions (reparse.py)

A learned parser is never approved silently: the gate needs every needs_review field
confirmed, at least 90% of held-out lines recognised and valid, and no field where the
parser disagrees with what the generic parser found.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.services.parser_generation import learned
from backend.services.parser_generation.learner import apply_edits, evaluate, learn, pending_review
from backend.services.parsing.formats import format_row
from backend.services.storage import db as db_module
from backend.services.vendors.envelope import split_envelope

MIN_PASS = 0.9
CLASS_NAMES = {0: "Base Event", 2004: "Detection Finding", 3002: "Authentication", 4001: "Network Activity"}


class WorkflowError(Exception):
    def __init__(self, message: str, status: int = 400, detail: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status = status
        self.detail = detail or {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db():
    return db_module.db


def get_format(format_id: str) -> Dict[str, Any]:
    with _db().get_connection() as conn:
        row = conn.execute("SELECT * FROM log_formats WHERE format_id = ?", (format_id,)).fetchone()
        if not row:
            raise WorkflowError(f"no log format {format_id}", 404)
        fmt = format_row(row)
        fmt["aliases"] = [r[0] for r in conn.execute("SELECT alias FROM log_format_aliases WHERE format_id = ?",
                                                     (format_id,))]
    return fmt


def samples(format_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    with _db().get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT raw_id, raw_text, source_name, added_at FROM log_format_samples WHERE format_id = ? "
            "ORDER BY id LIMIT ?", (format_id, limit))]


def format_detail(format_id: str, sample_limit: int = 20) -> Dict[str, Any]:
    from backend.services.parsing.dispatch import parse_log
    fmt = get_format(format_id)
    rows = samples(format_id, sample_limit)
    fmt["samples_shown"] = rows
    current = []
    for r in rows[:3]:
        parser, parsed = parse_log(r["raw_text"])
        tp = parsed.get("tracelog_parse") or {}
        current.append({"line": r["raw_text"], "parser": tp.get("parser") or parser,
                        "filled": {k: v["value"] for k, v in (tp.get("fields") or {}).items()},
                        "not_filled": {k: v.get("value") for k, v in (tp.get("not_filled") or {}).items()},
                        "unassigned_ips": tp.get("unassigned_ips") or []})
    fmt["parsed_now"] = current
    if fmt.get("parser_id"):
        try:
            fmt["parser"] = candidate(fmt["parser_id"])
        except WorkflowError:
            fmt["parser"] = None
    return fmt


def _row_to_view(r) -> Dict[str, Any]:
    spec = json.loads(r["rule_json"])
    val = json.loads(r["validation_json"]) if r["validation_json"] else None
    return {"id": r["id"], "name": r["name"], "vendor": r["vendor"], "product": r["product"],
            "class_uid": r["target_ocsf_class"], "class_name": CLASS_NAMES.get(r["target_ocsf_class"], ""),
            "status": r["status"], "created_at": r["created_at"], "updated_at": r["updated_at"],
            "approved_by": r["approved_by"], "approved_at": r["approved_at"], "spec": spec, "validation": val,
            "needs_review": [{"id": s["id"], "label": s["label"], "role": s["role"], "why": s["why"]}
                             for s in pending_review(spec)]}


def candidate(parser_id: str) -> Dict[str, Any]:
    with _db().get_connection() as conn:
        r = conn.execute("SELECT * FROM parsers WHERE id = ? AND format_type = 'learned'", (parser_id,)).fetchone()
    if not r:
        raise WorkflowError(f"no learned parser {parser_id}", 404)
    return _row_to_view(r)


def _save(conn, parser_id: str, spec: Dict[str, Any], validation: Dict[str, Any], **cols: Any) -> None:
    sets = ["rule_json = ?", "validation_json = ?", "tested = 1", "updated_at = ?"]
    args: List[Any] = [json.dumps(spec), json.dumps(validation), _now()]
    for k, v in cols.items():
        sets.append(f"{k} = ?")
        args.append(v)
    conn.execute(f"UPDATE parsers SET {', '.join(sets)} WHERE id = ?", (*args, parser_id))


def learn_format(format_id: str, name: Optional[str] = None, vendor: Optional[str] = None,
                 product: Optional[str] = None) -> Dict[str, Any]:
    fmt = get_format(format_id)
    lines = [r["raw_text"] for r in samples(format_id)]
    if len(lines) < 2:
        raise WorkflowError(f"format {format_id} has {len(lines)} sample line(s); at least 2 are needed "
                            f"(ideally 50 or more)")
    result = learn(lines)
    spec, validation = result["spec"], result["validation"]
    spec["format_ids"] = [format_id] + fmt.get("aliases", [])
    spec["name"] = name or (" ".join(x for x in (vendor, product) if x) + f" ({format_id})" if vendor or product
                            else f"{fmt['kind']} format {format_id}")
    spec["vendor"] = vendor or spec.get("vendor") or "Unknown"
    spec["product"] = product or spec.get("product") or f"Learned format {format_id}"
    parser_id = str(uuid.uuid4())
    now = _now()
    with _db().get_connection() as conn:
        conn.execute(
            "INSERT INTO parsers (id, name, vendor, product, format_type, description, target_ocsf_class, rule_json, "
            "status, created_at, updated_at, validation_json, tested) "
            "VALUES (?, ?, ?, ?, 'learned', ?, ?, ?, 'candidate', ?, ?, ?, 1)",
            (parser_id, spec["name"], spec["vendor"], spec["product"],
             f"Learned from {len(lines)} lines of format {format_id}: {fmt['template'][:200]}",
             spec["class_uid"], json.dumps(spec), now, now, json.dumps(validation)))
        conn.execute("UPDATE log_formats SET parser_id = ? WHERE format_id = ?", (parser_id, format_id))
        conn.commit()
    return candidate(parser_id)


def _retest(spec: Dict[str, Any], format_ids: List[str]) -> Dict[str, Any]:
    held = spec.get("held_out_lines") or []
    if held:
        return evaluate(spec, held, True)
    lines = [r["raw_text"] for fid in format_ids[:1] for r in samples(fid)]
    return evaluate(spec, lines, False)


def edit(parser_id: str, roles: Optional[Dict[str, Optional[str]]] = None, confirmed: Optional[List[str]] = None,
         reviewer: str = "reviewer", name: Optional[str] = None, vendor: Optional[str] = None,
         product: Optional[str] = None, class_uid: Optional[int] = None) -> Dict[str, Any]:
    """Apply a person's changes and test again. An approved parser that is edited goes back to candidate."""
    view = candidate(parser_id)
    spec = view["spec"]
    try:
        apply_edits(spec, roles, confirmed, reviewer)
    except ValueError as exc:
        raise WorkflowError(str(exc))
    for key, val in (("name", name), ("vendor", vendor), ("product", product)):
        if val:
            spec[key] = val
    if class_uid is not None:
        if class_uid not in CLASS_NAMES:
            raise WorkflowError(f"class {class_uid} is not one TRACELOG emits ({sorted(CLASS_NAMES)})")
        spec["class_uid"] = class_uid
    validation = _retest(spec, spec.get("format_ids") or [])
    with _db().get_connection() as conn:
        _save(conn, parser_id, spec, validation, name=spec.get("name") or view["name"],
              vendor=spec.get("vendor") or view["vendor"], product=spec.get("product") or view["product"],
              target_ocsf_class=spec["class_uid"], status="candidate", approved_by=None, approved_at=None)
        conn.commit()
    if view["status"] == "approved":
        with _db().get_connection() as conn:
            conn.execute("UPDATE log_formats SET status = 'new' WHERE parser_id = ? AND status = 'learned'",
                         (parser_id,))
            conn.commit()
        learned.invalidate()
    return candidate(parser_id)


def approval_blockers(view: Dict[str, Any]) -> List[str]:
    val = view.get("validation") or {}
    total = val.get("total_samples") or 0
    out = []
    if view["needs_review"]:
        out.append("fields that rest on position or weak evidence must be confirmed or changed: " +
                   ", ".join(f"{s['role']} ({s['label']})" for s in view["needs_review"]))
    if not total:
        out.append("the parser has not been tested")
    else:
        if val.get("recognised", 0) < MIN_PASS * total:
            out.append(f"it recognises only {val.get('recognised', 0)} of {total} held-out lines")
        if val.get("passed_samples", 0) < MIN_PASS * total:
            out.append(f"only {val.get('passed_samples', 0)} of {total} held-out lines parse cleanly")
    if val.get("disagreements"):
        d = val["disagreements"][0]
        out.append(f"it disagrees with the generic parser on {len(val['disagreements'])} value(s), e.g. "
                   f"{d['field']}: learned {d['learned']!r}, generic {d['generic']!r}")
    if not any(s.get("role") for s in view["spec"]["slots"]):
        out.append("it maps no fields")
    return out


def approve(parser_id: str, approved_by: str, confirmed: Optional[List[str]] = None) -> Dict[str, Any]:
    if not approved_by or not approved_by.strip():
        raise WorkflowError("approved_by is required: approvals are recorded with the approver's name")
    if confirmed:
        edit(parser_id, confirmed=confirmed, reviewer=approved_by)
    view = candidate(parser_id)
    blockers = approval_blockers(view)
    if blockers:
        raise WorkflowError("approval blocked: " + "; ".join(blockers), 400,
                            {"blockers": blockers, "needs_review": view["needs_review"]})
    now = _now()
    spec = view["spec"]
    compiled = learned.CompiledSpec(spec, parser_id, view["name"])
    with _db().get_connection() as conn:
        conn.execute("UPDATE parsers SET status = 'approved', approved_by = ?, approved_at = ?, updated_at = ? "
                     "WHERE id = ?", (approved_by.strip(), now, now, parser_id))
        # every format this parser reads, including variants seen before it existed
        claimed = list(spec.get("format_ids") or [])
        for r in conn.execute("SELECT format_id FROM log_formats WHERE status IN ('new', 'learned')").fetchall():
            if r[0] in claimed:
                continue
            s = conn.execute("SELECT raw_text FROM log_format_samples WHERE format_id = ? ORDER BY id LIMIT 1",
                             (r[0],)).fetchone()
            if s and _claims(compiled, s[0]):
                claimed.append(r[0])
        conn.executemany("UPDATE log_formats SET status = 'learned', parser_id = ? WHERE format_id = ?",
                         [(parser_id, fid) for fid in claimed])
        conn.commit()
    learned.invalidate()
    out = candidate(parser_id)
    out["formats"] = claimed
    out["reparse_candidates"] = reparse_candidates(claimed)
    return out


def _claims(compiled: "learned.CompiledSpec", line: str) -> bool:
    from backend.services.parsing.inference import fingerprint, structure
    env = split_envelope(line)
    st = structure(env.message)
    return compiled.score(st, fingerprint(st, env)["app"]) > 0


def reparse_candidates(format_ids: List[str]) -> int:
    if not format_ids:
        return 0
    marks = ",".join("?" * len(format_ids))
    with _db().get_connection() as conn:
        return conn.execute(
            f"SELECT COUNT(*) FROM raw_logs r JOIN normalized_events n ON n.raw_id = r.id AND n.superseded_by IS NULL "
            f"WHERE r.format_detected = 'generic_inferred' AND r.format_id IN ({marks})", format_ids).fetchone()[0]


def reject(parser_id: str) -> Dict[str, Any]:
    view = candidate(parser_id)
    with _db().get_connection() as conn:
        conn.execute("UPDATE parsers SET status = 'rejected', updated_at = ? WHERE id = ?", (_now(), parser_id))
        conn.execute("UPDATE log_formats SET status = 'new' WHERE parser_id = ? AND status = 'learned'", (parser_id,))
        conn.commit()
    if view["status"] == "approved":
        learned.invalidate()
    return candidate(parser_id)


def set_ignored(format_id: str, ignored: bool = True) -> Dict[str, Any]:
    get_format(format_id)
    with _db().get_connection() as conn:
        conn.execute("UPDATE log_formats SET status = ? WHERE format_id = ?", ("ignored" if ignored else "new",
                                                                                format_id))
        conn.commit()
    return get_format(format_id)
