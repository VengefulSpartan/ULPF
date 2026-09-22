"""
Learns a parser for one log format from many sample lines, then tests it on lines it did
not learn from.

One line cannot say what its values mean; a few hundred lines of the same format can:
  - which parts vary (values) and which never change (the format's words);
  - what each varying part always is: an IP address, a port, a protocol name, an action
    word, a time, a severity;
  - the words around it: "from", "to", "port", "src=", an arrow "a:p -> b:q";
  - how its values are distributed: a destination port has a few well-known values, a
    source port many high ones.

Each part of the line becomes a slot, and each slot gets a proposed field (or none) with a
confidence and the reason. A slot whose meaning rests on position alone (two addresses and
nothing saying which is the source) is proposed but flagged needs_review: a person confirms
it or changes it in Parser Studio before the parser can be approved.

The proposal is then tested on the held-out lines with exactly the code that will run in
production (learned.CompiledSpec): how many lines it recognises, how many values are valid,
and every field where it disagrees with the generic parser, which is only ever right when it
fills something.
"""
import random
import re
import statistics
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from backend.services.parser_generation.learned import (
    ARROWS, CompiledSpec, cells, cell_regex, masked_cell, pattern_groups,
)
from backend.services.parsing.inference import (
    AUTH_WORDS, EXACT, VALUE_CHECKS, _cef_severity, _unquote, as_action, as_ip, as_port, as_protocol, as_severity,
    as_time, fingerprint, infer, key_role, key_words, structure,
)
from backend.services.vendors.common import AUTHENTICATION, BASE_EVENT, DETECTION_FINDING, NETWORK_ACTIVITY
from backend.services.vendors.envelope import split_envelope

VALID = 0.95          # share of sample values that must pass a field's check
PRESENT = 0.9         # a key present in this share of samples is part of the format
REVIEW_BELOW = 0.8    # proposals below this confidence need a person to confirm them
PROPOSE_FROM = 0.5    # below this, a slot is listed but no field is proposed
MIN_HOLDOUT = 10
IANA_NUMBERS = {"1", "6", "17", "47", "50", "51", "58", "132"}


# ---------------------------------------------------------------------------------------------
# value profiling
# ---------------------------------------------------------------------------------------------
def _share(values: List[str], check) -> float:
    return sum(1 for v in values if check(v) is not None) / len(values) if values else 0.0


def value_type(values: List[str], placeholder: str = "") -> str:
    vals = [v for v in values if v not in (None, "", "-")]
    if not vals:
        return "empty"
    if placeholder == "<ACTION>" or _share(vals, as_action) >= VALID and not _share(vals, as_ip):
        return "action"
    if _share(vals, as_ip) >= VALID:
        return "ip"
    if all(v.isdigit() for v in vals):
        if all(len(v) >= 10 for v in vals) and _share(vals, as_time) >= VALID:
            return "time"
        return "port" if _share(vals, as_port) >= VALID else "int"
    if placeholder == "<PROTO>" or _share(vals, lambda v: as_protocol(v) if not v.isdigit() else None) >= VALID:
        return "protocol"
    if _share(vals, as_time) >= VALID:
        return "time"
    if _share(vals, as_severity) >= VALID:
        return "severity"
    return "text"


def _examples(values: List[str], k: int = 5) -> List[str]:
    seen: List[str] = []
    for v in values:
        if v not in seen:
            seen.append(v)
        if len(seen) == k:
            break
    return seen


def _port_profile(values: List[str]) -> str:
    nums = [int(v) for v in values if v.isdigit()]
    if len(nums) < 10:
        return "unknown"
    distinct = len(set(nums))
    if statistics.median(nums) >= 1024 and distinct >= 0.5 * len(nums):
        return "client"      # many different high ports: ephemeral source ports
    if sum(1 for n in nums if n < 1024) >= 0.8 * len(nums) or distinct <= 8:
        return "service"     # a few well-known ports: destination services
    return "unknown"


def _slot(sid, label, source, values, n, **extra) -> Dict[str, Any]:
    vals = [v for v in values if v not in (None, "", "-")]
    return {"id": sid, "label": label, "name": extra.pop("name", sid.replace(":", "_").replace(".", "_")),
            "source": source, "examples": _examples(vals), "distinct": len(set(vals)),
            "present": round(len(vals) / n, 3) if n else 0.0, "_values": vals,
            "type": extra.pop("type", None) or value_type(vals, extra.get("placeholder", "")),
            "role": None, "confidence": 0.0, "why": "", "needs_review": False, **extra}


# ---------------------------------------------------------------------------------------------
# profiling a format's samples into slots
# ---------------------------------------------------------------------------------------------
def _keyed_slots(parsed) -> Tuple[List[Dict[str, Any]], List[str]]:
    n = len(parsed)
    values: Dict[str, List[str]] = defaultdict(list)
    order: List[str] = []
    for _, env, st in parsed:
        seen = set()
        for k, v in st["pairs"]:
            if k in seen:
                continue
            seen.add(k)
            if k not in values:
                order.append(k)
            values[k].append(_unquote(str(v)).strip() if v is not None else "")
    anchor = [k for k in order if len(values[k]) >= PRESENT * n]
    slots = [_slot(f"k:{k}", k, {"key": k}, values[k], n, name=k) for k in order]
    return slots, anchor


def _cell_slots(parsed, kind) -> Tuple[List[Dict[str, Any]], List[str], Dict[int, str]]:
    """Slots for free text (one cell per token) or delimited lines (one cell per column)."""
    n = len(parsed)
    all_cells = [cells(kind, st) for _, _, st in parsed]
    width = min(len(c) for c in all_cells) if kind == "text" else max(len(c) for c in all_cells)
    width = min(width, 60)
    slots: List[Dict[str, Any]] = []
    template: List[str] = []
    literals: Dict[int, str] = {}
    word = "token" if kind == "text" else "column"
    for i in range(width):
        col = [c[i].strip() if i < len(c) else "" for c in all_cells]
        pats = Counter(masked_cell(v) for v in col)
        dom, count = pats.most_common(1)[0]
        has_ph = any("<" in t for t in dom)
        template.append(" ".join(dom) if count == n else "<*>")
        if not has_ph and count == n:
            literals[i] = col[0]
            continue
        if has_ph and count >= PRESENT * n:
            groups = pattern_groups(list(dom))
            rx = cell_regex(list(dom))
            gvals: List[List[str]] = [[] for _ in groups]
            for v in col:
                m = rx.fullmatch(v)
                for g in range(len(groups)):
                    gvals[g].append(_unquote(m.group(g + 1)) if m else "")
            if len(groups) > 1 and _share([v for v in col if v], as_time) >= VALID:
                slots.append(_slot(f"c:{i}", f"{word} {i + 1} '{' '.join(dom)}'", {"cell": i}, col, n,
                                   type="time", cell=i))
                continue
            for g, info in enumerate(groups):
                label = f"{word} {i + 1} '{' '.join(dom)}'" + (f" part {g + 1}" if len(groups) > 1 else "")
                slots.append(_slot(f"c:{i}.{g}", label, {"cell": i, "group": g, "pattern": list(dom)}, gvals[g], n,
                                   placeholder=info["placeholder"], before=info["before"], after=info["after"],
                                   cell=i, group=g))
        else:
            slots.append(_slot(f"c:{i}", f"{word} {i + 1} (varies)", {"cell": i}, [_unquote(v) for v in col], n,
                               cell=i))
    return slots, template, literals


def _header_slots(parsed) -> List[Dict[str, Any]]:
    n = len(parsed)
    out = []
    ts = [env.timestamp for _, env, _ in parsed if env.timestamp]
    if len(ts) >= PRESENT * n and _share(ts, as_time) >= VALID:
        out.append(_slot("h:timestamp", "syslog header timestamp", {"header": "timestamp"}, ts, n, type="time",
                         name="syslog_timestamp"))
    sev = [str(env.severity) for _, env, _ in parsed if env.severity is not None]
    if len(sev) >= PRESENT * n:
        out.append(_slot("h:severity", "syslog header severity (PRI)", {"header": "severity"}, sev, n,
                         type="severity", transform="syslog_severity", name="syslog_severity"))
    return out


# ---------------------------------------------------------------------------------------------
# proposing a field for each slot
# ---------------------------------------------------------------------------------------------
def _propose(slot, role, conf, why, review=False) -> None:
    if conf < PROPOSE_FROM:
        slot["alternatives"] = slot.get("alternatives", []) + [f"{role}? {why}"]
        return
    slot.update(role=role, confidence=round(conf, 2), why=why, needs_review=review or conf < REVIEW_BELOW)


def _valid_share(slot, role) -> float:
    if role == "severity" and slot.get("transform") == "cef_severity":
        return _share(slot["_values"], _cef_severity)
    if role == "severity" and slot.get("transform") == "syslog_severity":
        return 1.0
    return _share(slot["_values"], VALUE_CHECKS[role])


def _propose_keyed(slots, n) -> None:
    for s in slots:
        key = s["source"]["key"]
        if not s["_values"]:
            continue
        if key == "severity_raw":
            s["transform"] = "cef_severity"
            _propose(s, "severity", 0.9, "CEF header severity (0-10)")
            continue
        if key in ("event_name", "vendor", "product", "device_version", "cef_version", "signature_id"):
            continue
        role, conf, why = key_role(key)
        ok = _valid_share(s, role) if role else 0.0
        count = f"{round(ok * len(s['_values']))}/{len(s['_values'])} sample values are valid"
        if role and ok >= VALID:
            if len(s["_values"]) >= 50:
                conf = min(0.98, conf + 0.03)
            _propose(s, role, conf, f"{why}; {count}")
        elif role and ok >= 0.6:
            _propose(s, role, 0.6, f"{why}; only {count}", review=True)
        elif role:
            s["alternatives"] = [f"{role}? {why}, but only {count}"]
        elif s["type"] == "action":
            _propose(s, "action", 0.85, f"every value is an action word ({', '.join(s['examples'][:3])})")
        elif s["type"] == "protocol":
            _propose(s, "protocol", 0.8, f"every value is a protocol name ({', '.join(s['examples'][:3])})")
        elif s["type"] == "severity":
            _propose(s, "severity", 0.7, f"every value is a severity word ({', '.join(s['examples'][:3])})")
        elif s["type"] == "time":
            _propose(s, "time", 0.7, "every value is a plausible time")
        elif s["type"] == "ip":
            s["alternatives"] = ["an IP address; nothing in the key name says whether it is the source or "
                                 "destination"]


def _ctx(slot, literals: Dict[int, str], kind: str) -> str:
    """The word right before a value: inside its cell ('src=', 'SRC:'), else the literal token before it."""
    before = (slot.get("before") or "").strip()
    before = re.split(r"[\s,;|]", before)[-1] if before else ""
    word = before.strip("=:[](){}<>'\"-")
    if word:
        return word
    if kind == "text" and slot.get("group", 0) == 0 and "cell" in slot:
        for j in (slot["cell"] - 1, slot["cell"] - 2):
            if j in literals:
                return literals[j].strip(",.:;=()[]'\"").lower()
            if j < slot["cell"] - 1:
                break
    return ""


def _ctx_role(word: str) -> Tuple[Optional[str], float, str]:
    if not word:
        return None, 0.0, ""
    role, conf, _ = key_role(word)
    if role:
        return role, conf, f"the word before it is '{word}'"
    return None, 0.0, ""


def _propose_positional(slots, literals, kind, n) -> None:
    ordered = sorted([s for s in slots if "cell" in s], key=lambda s: (s["cell"], s.get("group", 0)))
    ips = [s for s in ordered if s["type"] == "ip"]
    # 1. an arrow inside a cell: a:p -> b:q
    for s in ordered:
        if s["type"] != "ip" or "group" not in s["source"]:
            continue
        pat = " ".join(s["source"]["pattern"])
        groups = pattern_groups(s["source"]["pattern"])
        literal = groups[0]["before"] + "".join(g["after"] for g in groups)   # the cell without its values
        arrow = next((a for a in ARROWS if a in literal), None)
        if not arrow:
            continue
        before_value = "".join(g["before"] for g in groups[:s["group"] + 1])
        seen_arrow = any(a in before_value for a in ARROWS)
        side = "dst" if seen_arrow else "src"
        _propose(s, f"{side}_ip", 0.9, f"{'right' if seen_arrow else 'left'} of the arrow '{arrow}' in "
                                         f"'{pat}' on every sample")
    # 2. the word before the value
    for s in ordered:
        if s["role"]:
            continue
        word = _ctx(s, literals, kind)
        s["context"] = word
        role, conf, why = _ctx_role(word)
        if not role:
            continue
        if s["type"] == "ip" and role in ("src_port", "dst_port"):
            continue
        if s["type"] == "ip" and role in ("src_ip", "dst_ip") or role not in ("src_ip", "dst_ip"):
            if _valid_share(s, role) >= VALID:
                _propose(s, role, min(conf, 0.9), f"{why}; every sample value is a valid "
                                                  f"{role.replace('_', ' ')}")
    # 3. ports next to their address: 'a:p' in one cell, or 'from a port p'
    for idx, s in enumerate(ordered):
        if s["role"] or s["type"] != "port":
            continue
        prev = ordered[idx - 1] if idx else None
        if prev and prev.get("cell") == s.get("cell") and prev["role"] in ("src_ip", "dst_ip") \
                and (s.get("before") or "").strip() in (":", "/", "."):
            side = prev["role"][:3]
            _propose(s, f"{side}_port", prev["confidence"], f"the port after the {'source' if side == 'src' else 'destination'}"
                                                            f" address in '{' '.join(s['source']['pattern'])}'",
                     review=prev["needs_review"])
        elif s.get("context") == "port":
            addr = next((p for p in reversed(ordered[:idx]) if p["role"] in ("src_ip", "dst_ip")
                         and s["cell"] - p["cell"] <= 3), None)
            if addr:
                side = addr["role"][:3]
                _propose(s, f"{side}_port", min(addr["confidence"], 0.85),
                         f"'port' follows the {'source' if side == 'src' else 'destination'} address",
                         review=addr["needs_review"])
    # 4. two addresses and nothing saying which is which: position only, a person must confirm
    undirected = [s for s in ips if not s["role"]]
    if not any(s["role"] in ("src_ip", "dst_ip") for s in ips) and len(undirected) >= 2:
        a, b = undirected[:2]
        more = len(undirected) - 2
        conf = 0.6 if not more else 0.5
        tail = f"; {more} more address field(s) left unassigned" if more else ""
        _propose(a, "src_ip", conf, f"first of the addresses in this format: position only, nothing in the line "
                                    f"says it is the source{tail}", review=True)
        _propose(b, "dst_ip", conf, f"second of the addresses: position only{tail}", review=True)
        after = [s for s in ordered if (s["cell"], s.get("group", 0)) > (b["cell"], b.get("group", 0))][:2]
        if len(after) == 2 and all(s["type"] == "port" and not s["role"] for s in after):
            p1, p2 = _port_profile(after[0]["_values"]), _port_profile(after[1]["_values"])
            note, pconf = "", conf
            if (p1, p2) == ("client", "service"):
                note, pconf = "; values fit a client port then a service port", conf + 0.05
            elif (p1, p2) == ("service", "client"):
                note, pconf = "; WARNING: values look like a service port then a client port", conf - 0.1
            _propose(after[0], "src_port", pconf, f"the number right after the two addresses{note}", review=True)
            _propose(after[1], "dst_port", pconf, f"the second number after the two addresses{note}", review=True)
    # 5. values that say what they are
    taken = {s["role"] for s in slots if s["role"]}
    for s in ordered:
        if s["role"]:
            continue
        if s["type"] == "action" and "action" not in taken:
            _propose(s, "action", 0.9 if s.get("placeholder") == "<ACTION>" else 0.85,
                     f"every value is an action word ({', '.join(s['examples'][:3])})")
        elif s["type"] == "protocol" and "protocol" not in taken:
            _propose(s, "protocol", 0.85, f"every value is a protocol name ({', '.join(s['examples'][:3])})")
        elif s["type"] == "time" and "time" not in taken:
            others = sum(1 for o in ordered if o["type"] == "time") - 1
            _propose(s, "time", 0.75, "every value is a plausible time" +
                     (f"; the first of {others + 1} times in the line (taken as the event's start)" if others else ""))
        elif s["type"] == "text" and "user" not in taken and s.get("context") in ("for", "as", "by") \
                and AUTH_WORDS.search(" ".join(literals.values())) and _valid_share(s, "user") >= VALID:
            _propose(s, "user", 0.6, f"follows '{s['context']}' in a login message: confirm it is the user",
                     review=True)
        elif s["type"] == "severity" and "severity" not in taken:
            _propose(s, "severity", 0.8, f"every value is a severity word ({', '.join(s['examples'][:3])})")
        elif s["type"] in ("port", "int") and "protocol" not in taken and set(s["_values"]) <= IANA_NUMBERS \
                and set(s["_values"]) & {"6", "17"} and s["distinct"] <= 4:
            _propose(s, "protocol", 0.55, "values are IANA protocol numbers (6 = TCP, 17 = UDP): numbers only, "
                                          "confirm", review=True)
        else:
            continue
        taken.add(s["role"])


def _resolve_conflicts(slots) -> None:
    """One slot per field: the most confident wins; the others keep it as an alternative."""
    by_role: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for s in slots:
        if s["role"]:
            by_role[s["role"]].append(s)
    for role, cands in by_role.items():
        if len(cands) < 2:
            continue
        cands.sort(key=lambda s: -s["confidence"])
        best = cands[0]
        for other in cands[1:]:
            if best["confidence"] - other["confidence"] < 0.05 and other["_values"][:20] != best["_values"][:20]:
                best["needs_review"] = True
                best["why"] += f"; {other['label']} also looks like {role.replace('_', ' ')}"
            other["alternatives"] = other.get("alternatives", []) + [f"{role}? {other['why']}"]
            other.update(role=None, confidence=0.0, why="", needs_review=False)


def _header_fallback(slots) -> None:
    roles = {s["role"]: s for s in slots if s["role"]}
    for s in slots:
        src = s["source"]
        if src.get("header") == "timestamp" and ("time" not in roles or roles["time"]["confidence"] < 0.85):
            if "time" in roles:
                roles["time"].update(role=None, alternatives=[f"time? {roles['time']['why']}"], needs_review=False)
            _propose(s, "time", 0.9, "the syslog header's timestamp, present on every sample")
            roles["time"] = s
        if src.get("header") == "severity" and "severity" not in roles:
            _propose(s, "severity", 0.9, "the syslog header's severity (0 = emergency ... 7 = debug)")
            roles["severity"] = s


def _class_for(slots, parsed) -> int:
    roles = {s["role"] for s in slots if s["role"]}
    if "signature" in roles:
        return DETECTION_FINDING
    if "user" in roles and sum(1 for _, env, _ in parsed if AUTH_WORDS.search(env.message)) >= PRESENT * len(parsed):
        return AUTHENTICATION
    if roles & {"src_ip", "dst_ip"}:
        return NETWORK_ACTIVITY
    return BASE_EVENT


def _action_map(slot) -> Dict[str, str]:
    return {v: a for v in sorted(set(slot["_values"]))[:50] if (a := as_action(v))}


# ---------------------------------------------------------------------------------------------
# learning and testing
# ---------------------------------------------------------------------------------------------
def _parse_all(lines: List[str]):
    out = []
    for line in lines:
        env = split_envelope(line)
        out.append((line, env, structure(env.message)))
    return out


def propose_spec(lines: List[str]) -> Dict[str, Any]:
    parsed = _parse_all(lines)
    kinds = Counter(st["kind"] for _, _, st in parsed)
    kind = kinds.most_common(1)[0][0]
    parsed = [p for p in parsed if p[2]["kind"] == kind]
    first_env, first_st = parsed[0][1], parsed[0][2]
    fp = fingerprint(first_st, first_env)
    n = len(parsed)
    spec: Dict[str, Any] = {"version": 1, "kind": kind, "delimiter": first_st["delimiter"], "app": fp["app"],
                            "samples_learned": n}
    if kind in ("kv", "json", "cef", "leef"):
        slots, anchor = _keyed_slots(parsed)
        _propose_keyed(slots, n)
        spec["anchor_keys"] = anchor
    else:
        slots, template, literals = _cell_slots(parsed, kind)
        _propose_positional(slots, literals, kind, n)
        spec["template"] = template
        if kind == "delimited":
            spec["columns"] = len(cells(kind, first_st))
    slots += _header_slots(parsed)
    _resolve_conflicts(slots)
    _header_fallback(slots)
    for s in slots:
        if s["role"] == "action":
            s["map"] = _action_map(s)
    if kind == "text":
        used = [s["source"]["cell"] for s in slots if s["role"] and "cell" in s["source"]]
        spec["match_prefix"] = max(min(len(spec["template"]), 4), (max(used) + 1) if used else len(spec["template"]))
    spec["class_uid"] = _class_for(slots, parsed)
    if kind in ("cef", "leef"):
        d = dict(first_st["pairs"])
        spec["vendor"], spec["product"] = str(d.get("vendor") or "Unknown"), str(d.get("product") or "Unknown")
    for s in slots:
        s.pop("_values", None)
    spec["slots"] = slots
    return spec


def _truthy_equal(role, a, b) -> bool:
    if role == "time":
        return str(a)[:19] == str(b)[:19]
    return str(a).lower() == str(b).lower()


def evaluate(spec: Dict[str, Any], lines: List[str], held_out: bool = True) -> Dict[str, Any]:
    """Run the spec exactly as production will, on lines it did not learn from."""
    from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
    compiled = CompiledSpec(spec, "", spec.get("name") or "candidate")
    per_field: Dict[str, Dict[str, int]] = defaultdict(lambda: {"filled": 0, "invalid": 0, "generic_filled": 0,
                                                                "agree": 0, "disagree": 0})
    disagreements, results, errors = [], [], []
    recognised = passed = drifted = 0
    roles = sorted({s["role"] for s in compiled.fields})
    for line in lines:
        env = split_envelope(line)
        st = structure(env.message)
        fp = fingerprint(st, env)
        _, gen = infer(line, env, st)
        gen_fields = {r: v["value"] for r, v in gen["tracelog_parse"]["fields"].items()}
        ok, error, extracted = False, None, None
        if not compiled.score(st, fp["app"]):
            error = "the learned parser does not recognise this line"
        else:
            recognised += 1
            hit, drift = compiled.apply(line, env, st, fp)
            if drift:
                drifted += 1
                error = "; ".join(drift["problems"][:3])
            else:
                parsed = hit[1]
                tp = parsed["tracelog_parse"]
                extracted = {r: v["value"] for r, v in tp["fields"].items()}
                for p in tp["rejected_values"]:
                    per_field[p.split("=")[0]]["invalid"] += 1
                bad = []
                for role in roles:
                    if role in extracted:
                        per_field[role]["filled"] += 1
                    if role in gen_fields:
                        per_field[role]["generic_filled"] += 1
                        if role in extracted:
                            if _truthy_equal(role, extracted[role], gen_fields[role]):
                                per_field[role]["agree"] += 1
                            else:
                                per_field[role]["disagree"] += 1
                                bad.append(role)
                                if len(disagreements) < 10:
                                    disagreements.append({"field": role, "learned": extracted[role],
                                                          "generic": gen_fields[role], "line": line[:300]})
                try:
                    ev = OCSFNormalizer.normalize(parsed, line, "test", "test", vendor=parsed.get("vendor"),
                                                  product=parsed.get("product"))
                    if ev.class_uid != (compiled.class_uid if compiled.class_uid is not None else ev.class_uid):
                        error = f"OCSF class {ev.class_uid}, expected {compiled.class_uid}"
                except Exception as exc:  # pragma: no cover - reported, never raised
                    error = f"OCSF normalisation failed: {exc}"
                if not error and not tp["rejected_values"] and not bad:
                    ok = True
                elif not error:
                    error = "; ".join(tp["rejected_values"][:2] + [f"disagrees with the generic parser on {r}"
                                                                   for r in bad])
        passed += ok
        if len(results) < 8 or (not ok and len(results) < 16):
            results.append({"sample_log": line[:1000], "passed": ok, "extracted_fields": extracted,
                            "error_message": error})
    total = len(lines)
    if not held_out:
        errors.append(f"only {total} sample lines: tested on the same lines it learned from (collect at least "
                      f"{MIN_HOLDOUT} for a held-out test)")
    return {
        "total_samples": total, "passed_samples": passed, "failed_samples": total - passed,
        "accuracy_score": round(100.0 * passed / total, 1) if total else 0.0,
        "recognised": recognised, "drifted": drifted, "held_out": held_out,
        "fields": {r: dict(per_field[r]) for r in roles},
        "gained": {r: per_field[r]["filled"] - per_field[r]["agree"] for r in roles
                   if per_field[r]["filled"] - per_field[r]["agree"] > 0},
        "disagreements": disagreements, "sample_results": results,
        "unmapped_fields": [s["label"] for s in spec["slots"] if not s.get("role") and s.get("distinct", 0) > 1][:30],
        "validation_errors": errors,
    }


def split(lines: List[str], seed: int = 7) -> Tuple[List[str], List[str], bool]:
    unique = list(dict.fromkeys(lines))
    if len(unique) < MIN_HOLDOUT:
        return unique, unique, False
    rng = random.Random(seed)
    shuffled = unique[:]
    rng.shuffle(shuffled)
    cut = max(1, int(len(shuffled) * 0.3))
    return shuffled[cut:], shuffled[:cut], True


def learn(lines: List[str], seed: int = 7) -> Dict[str, Any]:
    """{"spec", "validation"}: a proposed parser learned from 70% of the lines and tested on the other 30%."""
    lines = [l for l in lines if l and l.strip()]
    if not lines:
        raise ValueError("no sample lines to learn from")
    train, test, held_out = split(lines, seed)
    spec = propose_spec(train)
    spec["held_out_lines"] = test if held_out else []
    return {"spec": spec, "validation": evaluate(spec, test, held_out)}


def pending_review(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [s for s in spec["slots"] if s.get("role") and s.get("needs_review")]


def apply_edits(spec: Dict[str, Any], roles: Optional[Dict[str, Optional[str]]] = None,
                confirmed: Optional[List[str]] = None, reviewer: str = "reviewer") -> Dict[str, Any]:
    """A person's decisions: set or clear a slot's field, and confirm proposals that need review."""
    by_id = {s["id"]: s for s in spec["slots"]}
    for sid, role in (roles or {}).items():
        if sid not in by_id:
            raise ValueError(f"unknown slot {sid}")
        if role not in (None, "") and role not in VALUE_CHECKS:
            raise ValueError(f"unknown field {role}")
        s = by_id[sid]
        if (role or None) == s.get("role"):
            continue
        if role:
            for other in spec["slots"]:  # one slot per field
                if other is not s and other.get("role") == role:
                    other.update(role=None, confidence=0.0, needs_review=False,
                                 why=f"replaced by {s['label']} ({reviewer})")
            s.update(role=role, confidence=1.0, needs_review=False, why=f"set by {reviewer}")
            if role == "action":
                s["map"] = {v: a for v in s.get("examples", []) if (a := as_action(v))}
        else:
            s.update(role=None, confidence=0.0, needs_review=False, why=f"cleared by {reviewer}")
    for sid in confirmed or []:
        if sid not in by_id:
            raise ValueError(f"unknown slot {sid}")
        s = by_id[sid]
        if s.get("role") and s.get("needs_review"):
            s["needs_review"] = False
            s["why"] += f"; confirmed by {reviewer}"
    if spec["kind"] == "text":
        used = [s["source"]["cell"] for s in spec["slots"] if s.get("role") and "cell" in s["source"]]
        spec["match_prefix"] = max(min(len(spec["template"]), 4),
                                   (max(used) + 1) if used else len(spec["template"]))
    return spec
