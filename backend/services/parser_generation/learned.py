"""
Parsers learned from samples (learner.py) and approved by a person in Parser Studio.

A learned parser is data, not code: a spec saying which part of the line holds which
field. Approved specs are read from the `parsers` table and re-read within a few seconds
of any change, so an approval takes effect without a restart.

A learned parser only claims lines of the format it was learned from:
  key=value, JSON, CEF, LEEF   same kind and delimiter, and at least 80% of the keys that
                               were present in (nearly) every sample
  free text                    the same tokens (values masked) up to the last one it reads
  delimited                    same delimiter, number of columns and app

Every value it extracts is checked like any other parser's. In a positional format (free
text, delimited) two or more impossible values mean the device's format has drifted: the
line then goes to the generic parser instead of being passed on misaligned.
"""
import json
import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.services.parsing.inference import (
    AUTH_WORDS, KEYED_KINDS, VALUE_CHECKS, _cef_severity, _unquote, as_action, mask_token, structure,
    syslog_severity_label, tokens,
)
from backend.services.vendors.common import (
    AUTHENTICATION, BASE_EVENT, DETECTION_FINDING, NA_REFUSE, NA_TRAFFIC, NETWORK_ACTIVITY, event,
)

logger = logging.getLogger("tracelog.learned")

PACK = "learned"
RELOAD_SECONDS = 5.0
KEY_COVERAGE = 0.8

# placeholder in a masked token -> regex capturing the value it stands for
_PUNCT_L, _PUNCT_R = r"[(\[]*", r"[,.:;)\]]*"
PLACEHOLDER_RX = {
    "<IP>": r"((?:\d{1,3}\.){3}\d{1,3})",
    "<N>": r"(\d+)",
    "<Q>": r"(\"[^\"]*\"|'[^']*')",
    "<URL>": r"([a-zA-Z][a-zA-Z0-9+.-]*://\S+?)",
    "<MAC>": r"((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})",
    "<HOST>": r"((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})",
    "<HEX>": r"(0x[0-9A-Fa-f]+)",
    "<X>": r"([0-9a-fA-F]+)",
}
WHOLE_TOKEN = {"<ACTION>", "<PROTO>", "<*>"}   # masks that replace a whole token, punctuation included
_SPLIT = re.compile("(" + "|".join(re.escape(p) for p in PLACEHOLDER_RX) + ")")
ARROWS = ("->", "=>", "-->", "→", ">")


def token_parts(masked: str) -> List[str]:
    """'<IP>:<N>' -> ['', '<IP>', ':', '<N>', '']: literals at even, placeholders at odd positions."""
    if masked in WHOLE_TOKEN:
        return ["", masked, ""]
    return _SPLIT.split(masked)


def cell_regex(pattern: List[str]) -> re.Pattern:
    """Regex for a cell (a token, or a column of several tokens) from its masked tokens."""
    rx = []
    for masked in pattern:
        if masked in WHOLE_TOKEN:
            rx.append(_PUNCT_L + r"([^\s,;()\[\]]+?)" + _PUNCT_R if masked != "<*>" else r"(\S+)")
            continue
        rx.append("".join(PLACEHOLDER_RX[p] if i % 2 else re.escape(p) for i, p in enumerate(token_parts(masked))))
    return re.compile(r"\s+".join(rx))


def pattern_groups(pattern: List[str]) -> List[Dict[str, str]]:
    """For each capture group of cell_regex(pattern): the placeholder and the literal text before and after it."""
    groups: List[Dict[str, str]] = []
    pending = ""
    for ti, masked in enumerate(pattern):
        parts = token_parts(masked)
        for i, p in enumerate(parts):
            if i % 2:
                if groups:
                    groups[-1]["after"] = pending
                groups.append({"placeholder": p, "before": pending, "after": ""})
                pending = ""
            else:
                pending += p
        pending += " " if ti < len(pattern) - 1 else ""
    if groups:
        groups[-1]["after"] = pending
    return groups


def cells(kind: str, st: Dict[str, Any]) -> List[str]:
    if kind == "delimited":
        return [c.strip() for c in st.get("columns") or []]
    return tokens(st.get("text") or "")


def masked_cell(cell: str) -> Tuple[str, ...]:
    return tuple(mask_token(t) for t in tokens(cell)) or ("''",)


def _clean(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = _unquote(str(v)).strip()
    return None if s in ("", "-") else s


def convert(role: str, raw: Any, slot: Dict[str, Any]) -> Any:
    """The checked value for a field, or None when the raw value is not valid for it."""
    if raw is None:
        return None
    if role == "action":
        mapped = (slot.get("map") or {}).get(str(raw).strip())
        if mapped in ("allowed", "denied"):
            return mapped
        return as_action(raw)
    if role == "severity" and slot.get("transform") == "cef_severity":
        return _cef_severity(raw)
    if role == "severity" and slot.get("transform") == "syslog_severity":
        return syslog_severity_label(int(raw)) if str(raw).isdigit() else None
    return VALUE_CHECKS[role](raw)


class CompiledSpec:
    """An approved learned parser, ready to match and parse lines."""

    def __init__(self, spec: Dict[str, Any], parser_id: str = "", name: str = "", approved_by: str = "",
                 vendor: str = "", product: str = "", class_uid: Optional[int] = None):
        self.spec = spec
        self.parser_id = parser_id
        self.name = name or spec.get("name") or "learned parser"
        self.approved_by = approved_by
        self.vendor = vendor or spec.get("vendor") or "Unknown"
        self.product = product or spec.get("product") or "Learned format"
        self.class_uid = spec.get("class_uid") if class_uid is None else class_uid
        self.kind = spec["kind"]
        self.delimiter = spec.get("delimiter")
        self.app = spec.get("app") or ""
        self.fields = [s for s in spec.get("slots", []) if s.get("role")]
        self.all_slots = spec.get("slots", [])
        self.anchor = set(spec.get("anchor_keys") or [])
        self.template = spec.get("template") or []
        self.prefix = int(spec.get("match_prefix") or len(self.template))
        self.columns = spec.get("columns")
        self._rx: Dict[int, re.Pattern] = {}
        for s in self.all_slots:
            src = s["source"]
            if "pattern" in src and src["cell"] not in self._rx:
                self._rx[src["cell"]] = cell_regex(src["pattern"])

    @property
    def positional(self) -> bool:
        return self.kind in ("text", "delimited")

    # -- matching ------------------------------------------------------------------------------
    def score(self, st: Dict[str, Any], app: str, line_cells: Optional[List[str]] = None) -> float:
        if st["kind"] != self.kind:
            return 0.0
        if self.kind in KEYED_KINDS:
            if self.kind == "kv" and st["delimiter"] != self.delimiter:
                return 0.0
            if not self.anchor:
                return 0.0
            keys = {k for k, _ in st["pairs"]}
            cover = len(self.anchor & keys) / len(self.anchor)
            return cover if cover >= KEY_COVERAGE else 0.0
        if app != self.app:
            return 0.0
        line_cells = line_cells if line_cells is not None else cells(self.kind, st)
        if self.kind == "delimited":
            return 1.0 if st["delimiter"] == self.delimiter and len(line_cells) == self.columns else 0.0
        if len(line_cells) < self.prefix:
            return 0.0
        for want, tok in zip(self.template[:self.prefix], line_cells):
            if want != "<*>" and want != mask_token(tok):
                return 0.0
        return 1.0

    # -- extraction ----------------------------------------------------------------------------
    def raw_value(self, slot: Dict[str, Any], env, pairs: Dict[str, Any], line_cells: List[str]) -> Optional[str]:
        src = slot["source"]
        if "key" in src:
            return _clean(pairs.get(src["key"]))
        if "header" in src:
            return _clean(env.timestamp) if src["header"] == "timestamp" else \
                (str(env.severity) if env.severity is not None else None)
        i = src["cell"]
        if i >= len(line_cells):
            return None
        cell = line_cells[i].strip()
        if "group" not in src:
            return _clean(cell)
        m = self._rx[i].fullmatch(cell)
        return _clean(m.group(src["group"] + 1)) if m else None

    def apply(self, raw_text: str, env, st: Dict[str, Any], fp: Dict[str, Any]
              ) -> Tuple[Optional[Tuple[str, Dict[str, Any]]], Optional[Dict[str, Any]]]:
        pairs: Dict[str, Any] = {}
        for k, v in st.get("pairs") or []:
            pairs.setdefault(k, v)
        line_cells = cells(self.kind, st) if self.positional else []
        canonical: Dict[str, Any] = {}
        evidence: Dict[str, Dict[str, Any]] = {}
        problems: List[str] = []
        for slot in self.fields:
            role = slot["role"]
            raw = self.raw_value(slot, env, pairs, line_cells)
            if raw is None:
                continue
            value = convert(role, raw, slot)
            if value is None:
                problems.append(f"{role}={raw[:40]!r} from {slot['label']} is not a valid {role.replace('_', ' ')}")
                continue
            if role in canonical:
                continue
            canonical[role] = value
            evidence[role] = {"value": value, "from": slot["label"]}
        if self.positional and len(problems) >= 2:
            return None, {"parser_id": self.parser_id, "parser": self.name, "problems": problems[:10]}
        # an endpoint needs its address: a port alone is not half an endpoint
        for side in ("src", "dst"):
            if f"{side}_port" in canonical and f"{side}_ip" not in canonical:
                canonical.pop(f"{side}_port")
                evidence.pop(f"{side}_port", None)

        cls = self.class_uid
        if cls is None:
            cls = DETECTION_FINDING if "signature" in canonical else \
                AUTHENTICATION if "user" in canonical and AUTH_WORDS.search(env.message) else \
                NETWORK_ACTIVITY if ("src_ip" in canonical or "dst_ip" in canonical) else BASE_EVENT
        activity = (NA_REFUSE if canonical.get("action") == "denied" else NA_TRAFFIC) \
            if cls == NETWORK_ACTIVITY else None
        if "time" in canonical:
            canonical["timestamp"] = canonical.pop("time")
        if self.positional:
            vendor_fields = {}
            for slot in self.all_slots:
                if "header" in slot["source"]:
                    continue
                v = self.raw_value(slot, env, pairs, line_cells)
                if v is not None:
                    vendor_fields[slot.get("name") or slot["id"]] = v
        else:
            vendor_fields = dict(pairs)
        if problems:
            vendor_fields["_rejected_values"] = problems
        out = event(self.vendor, self.product, cls, activity, None, vendor_fields,
                    device_hostname=env.hostname, **canonical)
        out["_pack"] = PACK
        out["tracelog_parse"] = {
            "parser": f"learned: {self.name}", "parser_id": self.parser_id, "verified": True,
            "approved_by": self.approved_by, "confidence": 1.0,
            "format_id": fp["format_id"], "template": fp["template"],
            "structure": {"kind": st["kind"], "delimiter": st["delimiter"], "app": fp["app"], "size": fp["size"]},
            "fields": evidence, "rejected_values": problems[:10],
            "time_source": "device" if "timestamp" in canonical else "received",
        }
        return (f"{PACK}:{self.parser_id[:8]}" if self.parser_id else PACK, out), None


# ---------------------------------------------------------------------------------------------
# approved parsers, hot-reloaded
# ---------------------------------------------------------------------------------------------
_lock = threading.Lock()
_state: Dict[str, Any] = {"specs": [], "signature": None, "checked": 0.0, "db": None, "stale": True}


def invalidate() -> None:
    """Re-read approved parsers on the next line (called when one is approved, edited or rejected)."""
    with _lock:
        _state["stale"] = True


def _load() -> List[CompiledSpec]:
    from backend.services.storage import db as db_module
    database = db_module.db
    now = time.monotonic()
    with _lock:
        if _state["db"] is database and not _state.get("stale") and now - _state["checked"] < RELOAD_SECONDS:
            return _state["specs"]
    try:
        with database.get_connection() as conn:
            rows = conn.execute(
                "SELECT id, name, vendor, product, target_ocsf_class, rule_json, approved_by, updated_at "
                "FROM parsers WHERE status = 'approved' AND format_type = 'learned' ORDER BY approved_at").fetchall()
    except Exception:
        logger.exception("could not read learned parsers")
        rows = []
    signature = tuple((r["id"], r["updated_at"]) for r in rows)
    with _lock:
        if _state["db"] is not database or signature != _state["signature"]:
            specs = []
            for r in rows:
                try:
                    specs.append(CompiledSpec(json.loads(r["rule_json"]), r["id"], r["name"], r["approved_by"] or "",
                                              r["vendor"], r["product"], r["target_ocsf_class"]))
                except Exception:
                    logger.exception("learned parser %s could not be loaded", r["id"])
            _state.update(specs=specs, signature=signature)
            if specs:
                logger.info("loaded %d learned parser(s)", len(specs))
        _state.update(db=database, checked=now, stale=False)
        return _state["specs"]


def match_learned(raw_text: str, env, st: Optional[Dict[str, Any]] = None
                  ) -> Tuple[Optional[Tuple[str, Dict[str, Any]]], Optional[Dict[str, Any]]]:
    """(result, None) when an approved learned parser read the line; (None, drift) when the one that
    claims it found impossible values; (None, None) when none claims it."""
    specs = _load()
    if not specs:
        return None, None
    from backend.services.parsing.inference import fingerprint
    st = st or structure(env.message)
    fp = fingerprint(st, env)
    best, best_score = None, 0.0
    text_cells: Dict[str, List[str]] = {}
    for spec in specs:
        line_cells = None
        if spec.positional:
            line_cells = text_cells.setdefault(spec.kind, cells(spec.kind, st))
        s = spec.score(st, fp["app"], line_cells)
        if s > best_score:
            best, best_score = spec, s
    if not best:
        return None, None
    return best.apply(raw_text, env, st, fp)
