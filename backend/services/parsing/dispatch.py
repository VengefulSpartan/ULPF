"""
Single entry point for turning a raw log line into parsed fields.

Order:
  1. vendor packs (native formats of major perimeter devices), each result checked:
     if a pack claims a line but produces invalid values (an "address" that is not an
     IP, a port that is not a port) the device's format has drifted, e.g. after a
     firmware update shifted columns, and the pack's output is discarded rather than
     passed on misaligned;
  2. parsers learned from samples and approved in Parser Studio (they are checked the same
     way: impossible values in a positional format mean drift, and the line falls through);
  3. evidence-based inference, which fills only fields it can justify and labels the
     event unverified.

A line from a CSV file whose header row is known (csvheader.py) is read by column name before
any of these: the file's own header says what its columns are, where a positional pack could
only assume it. Its fields still come from the evidence rules, so it stays unverified.
"""
from typing import Any, Dict, List, Optional, Tuple

from backend.services.parsing.csvheader import pairs as csv_pairs
from backend.services.parsing.inference import as_ip, as_port, infer, structure
from backend.services.vendors import parse_vendor
from backend.services.vendors.envelope import split_envelope

_PROTO_OK = {"tcp", "udp", "icmp", "icmpv6", "ipv6-icmp", "gre", "esp", "ah", "sctp", "igmp", "ospf", "ipv6",
             "hopopt", "any", "ip"}


def validate_canonical(parsed: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(field, problem) for canonical values that are not what the field claims; empty when plausible."""
    problems = []
    for k in ("src_ip", "dst_ip"):
        v = parsed.get(k)
        if v not in (None, "") and not as_ip(v):
            problems.append((k, f"{k}={str(v)[:40]!r} is not an IP address"))
    for k in ("src_port", "dst_port"):
        v = parsed.get(k)
        if v not in (None, "") and as_port(v) is None:
            problems.append((k, f"{k}={str(v)[:40]!r} is not a port"))
    p = parsed.get("protocol")
    if p not in (None, "") and not (str(p).lower() in _PROTO_OK or (str(p).isdigit() and int(p) <= 255)):
        problems.append(("protocol", f"protocol={str(p)[:40]!r} is not a protocol"))
    return problems


# Packs that read fields by position: one shifted column misaligns everything after it
POSITIONAL_PACKS = {"paloalto_panos", "pfsense_filterlog"}


def parse_log(raw_text: str, csv_header: Optional[Dict[str, Any]] = None,
              csv_header_row: bool = False) -> Tuple[str, Dict[str, Any]]:
    """Returns (parser that produced the fields, parsed_fields).

    csv_header: the header of the CSV file this line came from ({"delimiter", "columns"}); a line
    with exactly those columns is read as (column name, value) pairs.
    csv_header_row: this line is that header. It is archived and chained like any line, marked as
    the header, and not counted as a new log format.
    """
    if csv_header_row:
        env = split_envelope(raw_text)
        fmt, parsed = infer(raw_text, env, structure(env.message))
        parsed["tracelog_parse"].update(csv_header_row=True,
                                        parser="CSV header row: the column names of the lines after it")
        return fmt, parsed
    if csv_header:
        cells = csv_pairs(raw_text, csv_header)
        if cells:
            st = {"kind": "csv", "delimiter": csv_header["delimiter"], "pairs": cells, "text": "", "prefix": ""}
            return infer(raw_text, split_envelope(raw_text), st)
    drift: Optional[Dict[str, Any]] = None
    hit = parse_vendor(raw_text)
    if hit:
        pack, parsed = hit
        problems = validate_canonical(parsed)
        if not problems:
            return pack, parsed
        if len(problems) < 2 and pack not in POSITIONAL_PACKS:
            # one odd value (an object name where an address should be, port 4294967295): drop that field,
            # keep the rest of the pack's work, and say what was dropped
            for field, _ in problems:
                parsed.setdefault("vendor_fields", {})[f"{field}_rejected"] = parsed.pop(field)
            parsed["tracelog_value_checks"] = [msg for _, msg in problems]
            return pack, parsed
        # several impossible values, or any in a positional format: the format has drifted
        drift = {"pack": pack, "problems": [msg for _, msg in problems]}

    env = split_envelope(raw_text)
    st = structure(env.message)
    from backend.services.parser_generation.learned import match_learned  # late import: registry reads the DB
    learned, learned_drift = match_learned(raw_text, env, st)
    if learned:
        if drift:
            learned[1]["tracelog_parse"]["pack_drift"] = drift
        return learned

    fmt, parsed = infer(raw_text, env, st)
    if drift:
        parsed["tracelog_parse"]["pack_drift"] = drift
        parsed["tracelog_parse"]["parser"] += f", after {drift['pack']} produced invalid values"
    if learned_drift:
        parsed["tracelog_parse"]["learned_drift"] = learned_drift
        parsed["tracelog_parse"]["parser"] += f", after learned parser '{learned_drift['parser']}' found " \
                                               f"invalid values"
    return fmt, parsed
