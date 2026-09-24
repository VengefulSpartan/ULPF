"""
Score TRACELOG on real log lines nobody on this team wrote.

    python scripts/evaluate_public_samples.py            # fetch the corpora (once), then score
    python scripts/evaluate_public_samples.py --no-fetch # score what is already downloaded
    python scripts/evaluate_public_samples.py --json     # machine-readable
    python scripts/evaluate_public_samples.py --markdown docs/PUBLIC_SAMPLES.md

Two public corpora, fetched from their upstream repositories at a pinned commit so every run
scores the same lines. Neither is committed here: they carry their owners' terms, and a copy
would go stale. They land in data/public_samples/, which git ignores.

  Elastic integrations   the sample logs Elastic's own parsers are tested against, for the
                         perimeter products listed below (37 of them have samples at the pinned
                         commit) — firewalls, IDS/IPS, WAFs, proxies, routers, DNS, NAC — each
                         paired with the event Elastic's parser produced from it. Those expected
                         events are an independent answer key: where they name a source or
                         destination address or port, ours is compared with theirs.
                         Terms: Elastic License 2.0 (github.com/elastic/integrations).
  Loghub                 2,000-line samples of real system logs collected for log-analytics
                         research (OpenSSH, Linux, Apache, Proxifier, Windows). No answer key:
                         scored for crashes, OCSF validity and which parser read them.
                         Terms: free for research and academic work (github.com/logpai/loghub).

What is measured, per line:
  crashed          the parser raised (must be 0: a line that breaks a parser is still archived,
                   but a crash is a bug)
  ocsf_invalid     the normalised event fails the OCSF checks
  parser           vendor pack, standard (CEF/LEEF), learned, or the evidence-based generic parser
  against the key  for each of source/destination address/port that Elastic's event names:
                   agree, WRONG (we filled a different value), missed (we left it empty); a value
                   we filled that the key does not name is counted as unverifiable, not as right

and end to end: every line is ingested through the real writer into a throwaway database —
archived, hashed, normalised, chained — and the chain is verified.

A disagreement is not an error until the answer key is shown to be right, and the answer key is
not always right. Each one is therefore explained only from evidence inside the corpus, and what
cannot be explained that way is listed line by line:
  key_conflict     another Elastic package reads the same message type the way TRACELOG does, with
                   no exception, while this package reads it the other way round (Elastic's
                   cisco_asa and cisco_ftd packages disagree on "Built outbound")
  built_message    a Cisco Teardown whose direction TRACELOG took from the same connection's Built
                   message; the report counts how often Elastic's own event for that Built message
                   names TRACELOG's source, i.e. how often Elastic contradicts itself
"""
import argparse
import glob
import ipaddress
import json
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DATA = ROOT / "data" / "public_samples"

ELASTIC = {
    "repo": "https://github.com/elastic/integrations",
    "commit": "e7570072592de12f31ad89b96603adc559c181ba",
    "packages": {
        # firewalls and next-generation firewalls
        "cisco_asa": "firewall", "cisco_ftd": "firewall", "panw": "firewall", "fortinet_fortigate": "firewall",
        "pfsense": "firewall", "sonicwall_firewall": "firewall", "checkpoint": "firewall",
        "juniper_srx": "firewall", "juniper_junos": "firewall", "juniper_netscreen": "firewall",
        "sophos": "firewall", "watchguard_firebox": "firewall", "barracuda_cloudgen_firewall": "firewall",
        "stormshield": "firewall", "arista_ngfw": "firewall", "iptables": "firewall", "cisco_meraki": "firewall",
        # routers and switches
        "cisco_ios": "router/switch", "cisco_nexus": "router/switch", "hpe_aruba_cx": "router/switch",
        # intrusion detection and prevention
        "snort": "IDS/IPS", "suricata": "IDS/IPS", "zeek": "IDS/IPS",
        # web application firewalls and load balancers
        "modsecurity": "WAF", "imperva": "WAF", "citrix_waf": "WAF", "f5_bigip": "WAF", "barracuda": "WAF",
        "radware": "WAF",
        # proxies and secure web gateways
        "squid": "proxy", "bluecoat": "proxy", "forcepoint_web": "proxy", "zscaler_zia": "proxy",
        "fortinet_fortiproxy": "proxy", "haproxy": "proxy",
        # DNS, DHCP and network access control
        "cisco_umbrella": "DNS/NAC", "infoblox_nios": "DNS/NAC", "cisco_ise": "DNS/NAC",
        # a standard format many devices emit
        "cef": "standard",
    },
}
LOGHUB = {
    "repo": "https://github.com/logpai/loghub",
    "commit": "dd61d0952749ee7963bde24220d1be5ede023033",
    "files": {"OpenSSH/OpenSSH_2k.log": "SSH server", "Linux/Linux_2k.log": "Linux system",
              "Apache/Apache_2k.log": "web server", "Proxifier/Proxifier_2k.log": "proxy client",
              "Windows/Windows_2k.log": "Windows"},
}
FIELDS = (("src_ip", ("source", "ip")), ("dst_ip", ("destination", "ip")),
          ("src_port", ("source", "port")), ("dst_port", ("destination", "port")))


# ---------------------------------------------------------------------------------------------
# fetching: partial clones, only the paths scored, at a pinned commit
# ---------------------------------------------------------------------------------------------
def _git(args: List[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def fetch(name: str, repo: str, commit: str, paths: List[str]) -> Path:
    target = DATA / name
    if not (target / ".git").exists():
        target.mkdir(parents=True, exist_ok=True)
        _git(["init", "-q"], target)
        _git(["remote", "add", "origin", repo], target)
    _git(["sparse-checkout", "set", "--no-cone", *paths], target)
    _git(["fetch", "-q", "--filter=blob:none", "--depth", "1", "origin", commit], target)
    _git(["checkout", "-q", commit], target)
    return target


def fetch_all() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    fetch("elastic", ELASTIC["repo"], ELASTIC["commit"],
          [f"packages/{p}/data_stream/*/_dev/test/pipeline" for p in ELASTIC["packages"]])
    fetch("loghub", LOGHUB["repo"], LOGHUB["commit"], list(LOGHUB["files"]))


# ---------------------------------------------------------------------------------------------
# reading the corpora into (source, category, line, expected event or None)
# ---------------------------------------------------------------------------------------------
# (source, category, line, expected event or None, file the line came from)
Sample = Tuple[str, str, str, Optional[Dict[str, Any]], str]


def _load_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def elastic_samples(root: Path) -> Iterator[Sample]:
    for package, category in ELASTIC["packages"].items():
        for path in sorted(glob.glob(str(root / "packages" / package / "data_stream" / "*" / "_dev" / "test" /
                                         "pipeline" / "test-*"))):
            if path.endswith("-expected.json") or path.endswith((".yml", ".yaml")):
                continue
            expected = (_load_json(path + "-expected.json") or {}).get("expected") or []
            docs = [d for d in expected if isinstance(d, dict)]
            if path.endswith(".json"):
                events = (_load_json(path) or {}).get("events") or []
                lines = [e.get("message") for e in events if isinstance(e, dict) and isinstance(e.get("message"), str)]
            else:
                with open(path, encoding="utf-8", errors="surrogateescape") as fh:
                    lines = [l.rstrip("\n") for l in fh if l.strip()]
            originals = [(d.get("event") or {}).get("original") for d in docs]
            if docs and all(isinstance(o, str) and o.strip() for o in originals):
                # every expected event names the line it came from: the pairing is exact, and it
                # handles multi-line fixtures, where lines and events do not correspond one to one
                for line, doc in zip(originals, docs):
                    yield package, category, line, doc, path
            elif docs and len(docs) == len(lines):
                for line, doc in zip(lines, docs):
                    yield package, category, line, doc, path
            else:
                for line in lines:
                    yield package, category, line, None, path


def loghub_samples(root: Path) -> Iterator[Sample]:
    for rel, category in LOGHUB["files"].items():
        path = root / rel
        if not path.exists():
            continue
        name = rel.split("/")[0]
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            for line in fh:
                if line.strip():
                    yield f"loghub:{name}", category, line.rstrip("\n"), None, str(path)


# ---------------------------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------------------------
def _dig(doc: Dict[str, Any], path: Tuple[str, str]) -> Any:
    value: Any = doc
    for part in path:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _same(field: str, ours: Any, theirs: Any) -> bool:
    if isinstance(theirs, list):  # a few pipelines emit a list (f5_bigip, zscaler_zia): any element matches
        return any(_same(field, ours, t) for t in theirs)
    if field.endswith("_ip"):
        try:
            return ipaddress.ip_address(str(ours)) == ipaddress.ip_address(str(theirs))
        except ValueError:
            return str(ours) == str(theirs)
    try:
        return int(ours) == int(theirs)
    except (TypeError, ValueError):
        return False


_CONNECTION_ID = re.compile(r"(?:Built (?:inbound|outbound) [A-Z]+|Teardown [A-Z]+) connection (\d+)")
_CISCO_ID = re.compile(r"%(?:ASA|FTD)-\d-(\d{6}): ?(?:Built (inbound|outbound))?")
OPPOSITE = {"src_ip": "dst_ip", "dst_ip": "src_ip", "src_port": "dst_port", "dst_port": "src_port"}


def message_key(line: str) -> Optional[str]:
    """The message type, for products that name one, so the same message can be compared across
    packages. Cisco ASA and FTD share their syslog catalogue: id plus Built direction."""
    m = _CISCO_ID.search(line)
    if m:
        return f"{m.group(1)} {m.group(2) or ''}".strip()
    return None


def parser_group(fmt: str, parsed: Dict[str, Any]) -> str:
    tp = parsed.get("tracelog_parse") or {}
    if fmt == "parse_error":
        return "error"
    if tp.get("standard"):
        return "standard"
    if str(tp.get("parser_pack") or fmt).startswith("learned"):
        return "learned"
    if fmt == "generic_inferred":
        return "generic"
    return "pack"


def score(samples: List[Sample]) -> Dict[str, Any]:
    from backend.services.normalization.ocsf_export import to_ocsf, validate
    from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
    from backend.services.parsing.dispatch import parse_log

    per_source: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"lines": 0, "crashed": 0, "ocsf_invalid": 0,
                                                                 "parsers": Counter(), "classes": Counter(),
                                                                 "keyed": 0, "agree": 0, "wrong": 0, "missed": 0,
                                                                 "missed_unstated": 0, "unverifiable": 0})
    # how each package's answer key treats each message type: {message key: {package: Counter(agree/wrong)}}
    by_message: Dict[str, Dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    disagreements: List[Dict[str, Any]] = []
    # Elastic's own source address for each Built message, so a Teardown's direction can be checked
    # against what Elastic itself said about the same connection: {(file, connection id): source ip}
    elastic_built: Dict[Tuple[str, str], Any] = {}
    invalid_examples: List[Dict[str, Any]] = []
    crash_examples: List[Dict[str, Any]] = []
    from backend.services.vendors import cisco
    current_file = None
    for source, category, line, doc, path in samples:
        if path != current_file:
            # each fixture file is a separate capture: a Teardown must not find its Built message
            # in another file that happens to reuse the same hostname and connection id
            cisco.OPEN_CONNECTIONS.clear()
            current_file = path
        s = per_source[source]
        s["category"] = category
        s["lines"] += 1
        try:
            fmt, parsed = parse_log(line)
            ev = OCSFNormalizer.normalize(parsed, line, "raw", "hash").model_dump()
        except Exception as exc:  # a crash is the finding
            s["crashed"] += 1
            if len(crash_examples) < 20:
                crash_examples.append({"source": source, "error": repr(exc)[:200], "line": line[:300]})
            continue
        s["parsers"][parser_group(fmt, parsed)] += 1
        s["classes"][ev.get("class_name")] += 1
        problems = validate(to_ocsf(ev))
        if problems:
            s["ocsf_invalid"] += 1
            if len(invalid_examples) < 20:
                invalid_examples.append({"source": source, "problems": problems[:3], "line": line[:300]})
        if doc is None:
            continue
        ours = {"src_ip": (ev.get("src_endpoint") or {}).get("ip"), "dst_ip": (ev.get("dst_endpoint") or {}).get("ip"),
                "src_port": (ev.get("src_endpoint") or {}).get("port"),
                "dst_port": (ev.get("dst_endpoint") or {}).get("port")}
        s["keyed"] += 1
        key = message_key(line)
        connection = _CONNECTION_ID.search(line) if key else None
        if connection and key.startswith(("302013", "302015")):
            elastic_built[(path, connection.group(1))] = _dig(doc, ("source", "ip"))
        vendor = (parsed.get("vendor_fields") or {})
        for field, where in FIELDS:
            theirs = _dig(doc, where)
            mine = ours[field]
            if theirs in (None, "", []):
                if mine not in (None, ""):
                    s["unverifiable"] += 1
                continue
            if mine in (None, ""):
                s["missed"] += 1
                if vendor.get("direction_source") == "not seen":
                    s["missed_unstated"] += 1
            elif _same(field, mine, theirs):
                s["agree"] += 1
                if key:
                    by_message[key][source]["agree"] += 1
            else:
                s["wrong"] += 1
                if key:
                    by_message[key][source]["wrong"] += 1
                other = ours[OPPOSITE[field]]
                disagreements.append({"source": source, "field": field, "ours": mine, "elastic": theirs,
                                      "reversed": other not in (None, "") and _same(field, other, theirs),
                                      "direction_source": vendor.get("direction_source"), "message": key,
                                      "our_source": ours["src_ip"],
                                      "elastic_built_source": elastic_built.get((path, connection.group(1)))
                                      if connection else None,
                                      "parser": fmt, "line": line[:300]})
    for d in disagreements:
        d["cause"], d["evidence"] = explain(d, by_message)
    for s in per_source.values():
        s["parsers"] = dict(s["parsers"])
        s["classes"] = dict(s["classes"])
    return {"per_source": dict(per_source), "disagreements": disagreements,
            "invalid_examples": invalid_examples, "crash_examples": crash_examples}


CAUSES = {
    "key_conflict": "Elastic's packages read this message in opposite directions",
    "built_message": "Direction taken from the connection's own Built message",
    "other": "Not explained — listed line by line",
}


def explain(d: Dict[str, Any], by_message: Dict[str, Dict[str, Counter]]) -> Tuple[str, str]:
    """Why a disagreement happened, from evidence in the corpus itself, never from a list of excuses.

    built_message  TRACELOG took the direction of a Teardown from the Built message for the same
                   connection, which says who opened it; Elastic reads the Teardown in written order.
    key_conflict   the same message type is keyed by another Elastic package the way TRACELOG reads
                   it, with no exception, while this package keys it the other way round.
    """
    if d["reversed"] and d["direction_source"] == "built message":
        built = d["elastic_built_source"]
        if built is None:
            return "built_message", "no_built_event"
        return "built_message", ("elastic_built_agrees" if _same("src_ip", d["our_source"], built)
                                 else "elastic_built_reversed")
    if d["reversed"] and d["message"]:
        mine = by_message[d["message"]][d["source"]]
        for package, c in by_message[d["message"]].items():
            if package != d["source"] and c["agree"] and not c["wrong"] and not mine["agree"]:
                return "key_conflict", (f"Elastic's {package} package agrees with TRACELOG on all {c['agree']} "
                                        f"fields of message {d['message']}; its {d['source']} package reverses "
                                        f"all {mine['wrong']}")
    return "other", ""


def ingest_end_to_end(samples: List[Sample]) -> Dict[str, Any]:
    """Every line through the real writer into a throwaway database, then verify the chain."""
    from scripts.benchmark import setup_database
    tmp = tempfile.TemporaryDirectory()
    database = setup_database(Path(tmp.name) / "public.db")
    from backend.services.ingestion.stream import InboundRecord, StreamIngestor
    from backend.services.integrity.ledger import IntegrityLedger

    from backend.services.vendors import cisco
    cisco.OPEN_CONNECTIONS.clear()
    ingestor = StreamIngestor()
    stored = 0
    started = time.perf_counter()
    for i in range(0, len(samples), 1000):
        records = [InboundRecord(raw=line.encode("utf-8", "surrogateescape"), transport="file",
                                 input_name=source, hints={"source_name": source})
                   for source, _, line, _, _ in samples[i:i + 1000]]
        stored += len(ingestor.ingest(records))
    seconds = time.perf_counter() - started
    verdict = IntegrityLedger.verify_chain()
    with database.get_connection() as conn:
        archived = conn.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0]
    database.close()
    tmp.cleanup()
    return {"submitted": len(samples), "stored": stored, "archived": archived, "chain_valid": verdict.is_valid,
            "chain_records": verdict.total_records, "seconds": round(seconds, 1),
            "events_per_second": round(stored / seconds) if seconds else None}


# ---------------------------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------------------------
def by_cause(disagreements: List[Dict[str, Any]]) -> Counter:
    return Counter(d["cause"] for d in disagreements)


def totals(per_source: Dict[str, Dict[str, Any]], loghub: bool = False) -> Counter:
    rows = [s for k, s in per_source.items() if k.startswith("loghub:") == loghub]
    t = Counter()
    for s in rows:
        for k in ("lines", "crashed", "ocsf_invalid", "keyed", "agree", "wrong", "missed", "missed_unstated",
                  "unverifiable"):
            t[k] += s[k]
        for k, v in s["parsers"].items():
            t["parser_" + k] += v
    return t


def markdown(result: Dict[str, Any]) -> str:
    ps = result["per_source"]
    e, l = totals(ps), totals(ps, loghub=True)
    e2e = result["end_to_end"]
    all_lines = e["lines"] + l["lines"]
    scored = e["agree"] + e["wrong"] + e["missed"]
    causes = by_cause(result["disagreements"])
    out = [
        "# TRACELOG on real, third-party logs",
        "",
        "Generated by `python scripts/evaluate_public_samples.py --markdown docs/PUBLIC_SAMPLES.md`. Every line",
        "below was written by a real device or system, collected by someone else, and fetched from its",
        "upstream repository at a pinned commit; none of it was written by this team.",
        "",
        "## Summary",
        "",
        "| | |",
        "|---|---|",
        f"| Real log lines processed | **{all_lines:,}** from {len(ps)} sources |",
        f"| Crashes | **{e['crashed'] + l['crashed']}** |",
        f"| Events failing OCSF validation | **{e['ocsf_invalid'] + l['ocsf_invalid']}** |",
        f"| Archived, hashed and hash-chained end to end | **{e2e['archived']:,}** of {e2e['submitted']:,}, "
        f"chain {'verified' if e2e['chain_valid'] else 'FAILED verification'} "
        f"({e2e['events_per_second']:,} events/s on this machine) |",
        f"| Address and port fields checked against Elastic's parsers | **{scored:,}**: {e['agree']:,} agree, "
        f"**{e['wrong']:,} disagree** ({causes['other']:,} unexplained), {e['missed']:,} left empty |",
        "",
        "Elastic's own parsers produced an expected event for each of their sample lines. Where that event names a",
        "source or destination address or port, TRACELOG's value is compared with it: *agree*, *disagree* (a",
        "different value), or *left empty* (the line gives no evidence, or no pack reads that product yet). A",
        f"value TRACELOG filled that Elastic's event does not name is not counted as right; there were "
        f"{e['unverifiable']:,} of those. Every disagreement is explained below from evidence in the corpus, or",
        "listed line by line.",
        "",
        "## Perimeter devices — Elastic integrations sample logs, with an answer key",
        "",
        "| Product | Kind | Lines | Crashes | OCSF-invalid | Vendor pack | Standard | Generic | Agree | Disagree | Left empty |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, s in sorted(ps.items(), key=lambda kv: (kv[1]["category"], kv[0])):
        if name.startswith("loghub:"):
            continue
        p = s["parsers"]
        out.append(f"| {name} | {s['category']} | {s['lines']:,} | {s['crashed']} | {s['ocsf_invalid']} | "
                   f"{p.get('pack', 0):,} | {p.get('standard', 0):,} | {p.get('generic', 0):,} | {s['agree']:,} | "
                   f"{s['wrong']:,} | {s['missed']:,} |")
    out.append(f"| **all** | | **{e['lines']:,}** | **{e['crashed']}** | **{e['ocsf_invalid']}** | "
               f"**{e['parser_pack']:,}** | **{e['parser_standard']:,}** | **{e['parser_generic']:,}** | "
               f"**{e['agree']:,}** | **{e['wrong']:,}** | **{e['missed']:,}** |")
    out += ["", "## Systems — Loghub samples, no answer key", "",
            "| Source | Kind | Lines | Crashes | OCSF-invalid | Read by | Classes |",
            "|---|---|---:|---:|---:|---|---|"]
    for name, s in sorted(ps.items()):
        if not name.startswith("loghub:"):
            continue
        readers = ", ".join(f"{k} {v:,}" for k, v in sorted(s["parsers"].items(), key=lambda kv: -kv[1]))
        classes = ", ".join(f"{k} {v:,}" for k, v in sorted(s["classes"].items(), key=lambda kv: -kv[1]))
        out.append(f"| {name.split(':', 1)[1]} | {s['category']} | {s['lines']:,} | {s['crashed']} | "
                   f"{s['ocsf_invalid']} | {readers} | {classes} |")
    out += ["", "## Every disagreement, explained", "",
            "A disagreement is explained only by evidence the corpus itself contains; anything else is listed in",
            "full under *not explained*.", "",
            "| Cause | Fields | Evidence | Example |", "|---|---:|---|---|"]
    for cause in ("key_conflict", "built_message", "other"):
        rows = [d for d in result["disagreements"] if d["cause"] == cause]
        if not rows or cause == "other":
            continue
        if cause == "built_message":
            n = Counter(d["evidence"] for d in rows)
            evidence = [f"on {n['elastic_built_agrees']:,} of these fields, Elastic's own event for the same "
                        f"connection's Built message names TRACELOG's source"]
            if n["elastic_built_reversed"]:
                evidence.append(f"on {n['elastic_built_reversed']:,}, that Built event is itself one of the reversed "
                                "ones in the row above")
            if n["no_built_event"]:
                evidence.append(f"{n['no_built_event']:,} have no Elastic event for the Built message")
        else:
            evidence = sorted({d["evidence"] for d in rows})
        ex = rows[0]
        out.append(f"| {CAUSES[cause]} | {len(rows):,} | {'; '.join(evidence)} | {ex['source']} {ex['field']}: "
                   f"TRACELOG `{ex['ours']}`, Elastic `{ex['elastic']}` — `{ex['line'][:120].replace('|', '/')}` |")
    if causes["built_message"]:
        out += ["", "Cisco ASA and FTD write the outside end of a connection first in both the Built and the Teardown",
                "message, and only the Built message says which end opened it. TRACELOG reads a Teardown's direction",
                "from its own Built message (matched by device, connection id and both ends); Elastic's pipeline",
                "reads the Teardown in written order, which makes an outbound DNS lookup's teardown come *from* port",
                f"53. {e['missed_unstated']:,} Teardown fields whose Built message is not in the sample are left empty",
                "rather than guessed."]
    others = [d for d in result["disagreements"] if d["cause"] == "other"]
    out += ["", f"### Not explained ({len(others):,})", ""]
    if others:
        out += ["| Product | Field | TRACELOG | Elastic | Line |", "|---|---|---|---|---|"]
        for w in others:
            out.append(f"| {w['source']} | {w['field']} | `{w['ours']}` | `{w['elastic']}` | "
                       f"`{w['line'][:160].replace('|', '/')}` |")
    else:
        out.append("None.")
    out += ["", "## Sources and terms", "",
            f"- Elastic integrations, commit `{ELASTIC['commit'][:12]}`, `packages/*/data_stream/*/_dev/test/pipeline`"
            " — Elastic License 2.0. Fetched, not redistributed.",
            f"- Loghub, commit `{LOGHUB['commit'][:12]}`, the `*_2k.log` samples — free for research and academic "
            "use; cite the Loghub paper (Zhu et al., ISSRE 2023). Fetched, not redistributed.", ""]
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="Score TRACELOG on real third-party logs")
    ap.add_argument("--no-fetch", action="store_true", help="use what is already in data/public_samples")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--markdown", metavar="PATH", help="also write the report as Markdown")
    args = ap.parse_args()
    if not args.no_fetch:
        fetch_all()
    samples = list(elastic_samples(DATA / "elastic")) + list(loghub_samples(DATA / "loghub"))
    if not samples:
        sys.exit("no samples found: run without --no-fetch first")
    result = score(samples)
    result["end_to_end"] = ingest_end_to_end(samples)
    if args.markdown:
        Path(args.markdown).write_text(markdown(result), encoding="utf-8")
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return
    ps = result["per_source"]
    e, l = totals(ps), totals(ps, loghub=True)
    e2e = result["end_to_end"]
    print(f"\n{e['lines'] + l['lines']:,} real lines from {len(ps)} sources")
    print(f"  crashes {e['crashed'] + l['crashed']}, OCSF-invalid {e['ocsf_invalid'] + l['ocsf_invalid']}")
    print(f"  perimeter (Elastic): {e['lines']:,} lines; vendor pack {e['parser_pack']:,}, standard "
          f"{e['parser_standard']:,}, generic {e['parser_generic']:,}")
    causes = by_cause(result["disagreements"])
    print(f"  against Elastic's parsers: agree {e['agree']:,}, DISAGREE {e['wrong']:,}, left empty {e['missed']:,}, "
          f"unverifiable {e['unverifiable']:,}")
    for cause, n in causes.most_common():
        print(f"    disagree, {CAUSES[cause].lower()}: {n:,}")
    print(f"  end to end: {e2e['archived']:,}/{e2e['submitted']:,} archived and chained, chain "
          f"{'verified' if e2e['chain_valid'] else 'FAILED'}, {e2e['events_per_second']:,} events/s")


if __name__ == "__main__":
    main()
