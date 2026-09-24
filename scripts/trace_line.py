"""
Follow one log line through TRACELOG and print what every stage made of it.

    python scripts/trace_line.py                      # the FortiGate example in docs/END_TO_END_FLOW.md
    python scripts/trace_line.py --line '<134>...'    # any line of your own

It runs the real code — the writer, the parsers, the OCSF normaliser, the chain, the Splunk HEC,
CEF and LEEF formatters and the delivery ledger — against a throwaway database, so it changes
nothing. The one thing it does not do is open a network connection: the Splunk HEC request is
built exactly as the output builds it and printed instead of sent. Event ids differ on every run;
the raw hash depends only on the line.
"""
import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

EXAMPLE = ('<189>date=2026-09-21 time=15:50:00 devname="FGT-HQ" devid="FG100FTK19000001" logid="0000000013" '
           'type="traffic" subtype="forward" level="notice" vd="root" eventtime=1789986000000000000 tz="+0530" '
           'srcip=10.1.1.20 srcport=52211 srcintf="port2" dstip=198.51.100.25 dstport=443 dstintf="wan1" '
           'proto=6 action="deny" policyid=12 service="HTTPS" sentbyte=0 rcvdbyte=0')


def section(title: str) -> None:
    print(f"\n=== {title} " + "=" * max(0, 86 - len(title)))


def show(obj) -> None:
    print(json.dumps(obj, indent=2, default=str, ensure_ascii=False))


class _Captured:
    """Stands in for the HTTP client: keeps the request instead of sending it."""
    status_code, text = 200, '{"text":"Success","code":0}'

    def __init__(self):
        self.requests = []

    def post(self, url, content=None, headers=None, **_):
        self.requests.append({"url": url, "headers": headers, "body": content})
        return self


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--line", default=EXAMPLE, help="the log line to follow (default: a FortiGate traffic log)")
    ap.add_argument("--peer", default="192.0.2.10", help="address the line appears to come from")
    args = ap.parse_args()
    raw = args.line.encode("utf-8") + b"\n"          # as it arrives over syslog, terminator included

    from scripts.benchmark import setup_database
    database = setup_database(Path(tempfile.mkdtemp()) / "trace.db")
    from backend.connectors.config import Output
    from backend.connectors.outputs.formats import cef, leef
    from backend.connectors.outputs.http_sinks import SplunkHecSink
    from backend.services.ingestion.stream import InboundRecord, StreamIngestor
    from backend.services.integrity.delivery_ledger import DeliveryLedger
    from backend.services.integrity.hasher import Hasher
    from backend.services.integrity.ledger import IntegrityLedger
    from backend.services.parsing.dispatch import parse_log

    DeliveryLedger.register_output("splunk", "splunk_hec", "https://splunk.example:8088")

    section("1. Received: the bytes, as a syslog UDP datagram")
    print(f"{len(raw)} bytes from {args.peer}; last 40: {raw[-40:]!r}")

    section("2. Parsed")
    fmt, parsed = parse_log(args.line)
    print(f"parser: {fmt}")
    show({k: v for k, v in parsed.items() if k not in ("vendor_fields", "tracelog_parse")})

    stored = StreamIngestor().ingest([InboundRecord(raw=raw, transport="syslog-udp", input_name="syslog-udp",
                                                    peer_ip=args.peer)])
    ev = stored[0]
    with database.get_connection() as conn:
        raw_row = dict(conn.execute("SELECT * FROM raw_logs WHERE id = ?", (ev.raw_id,)).fetchone())
        source = dict(conn.execute("SELECT name, vendor, product FROM sources WHERE id = ?",
                                   (ev.source_id,)).fetchone())
        link = dict(conn.execute("SELECT * FROM integrity_ledger WHERE event_id = ?", (ev.event_id,)).fetchone())
        stored_json = conn.execute("SELECT normalized_json FROM normalized_events WHERE id = ?",
                                   (ev.event_id,)).fetchone()[0]

    section("3. Archived: the raw_logs row (raw_text omitted)")
    show({k: v for k, v in raw_row.items() if k != "raw_text"})
    body = raw.rstrip(b"\n")
    print(f"SHA-256 of the bytes received, computed here: {hashlib.sha256(body).hexdigest()}")
    print(f"raw_text.encode(raw_encoding) == bytes received: "
          f"{raw_row['raw_text'].encode(raw_row['raw_encoding']) == body}")

    section("4. Source registered")
    show(source)

    section("5. Normalised: the OCSF event outputs receive")
    show(ev.ocsf)

    section("6. Chained: the integrity_ledger row")
    show(link)
    again = Hasher.compute_record_hash(link["prev_hash"], link["sequence_num"], link["raw_hash"], stored_json)
    print(f"SHA-256(prev_hash : sequence_num : raw_hash : canonical JSON of {len(stored_json)} bytes), "
          f"recomputed: {again}  matches: {again == link['record_hash']}")

    section("7. Delivered: the Splunk HEC request, built by the output and captured")
    sink = SplunkHecSink(Output(name="splunk", type="splunk_hec",
                                settings={"url": "https://splunk.example:8088", "token": "<HEC token>"}),
                         data_dir=tempfile.mkdtemp())
    sink._http = _Captured()
    sink.send([ev.ocsf])
    request = sink._http.requests[0]
    print(f"POST {request['url']}")
    print(f"Authorization: {request['headers']['Authorization']}")
    show(json.loads(request["body"]))
    print("\nThe same event as CEF (ArcSight and most SIEM syslog inputs):")
    print(cef(ev.ocsf))
    print("\nand as LEEF 2.0 (QRadar):")
    print(leef(ev.ocsf))

    section("8. Recorded: the delivery ledger")
    DeliveryLedger.record("splunk", "delivered", "live", [ev.ocsf])
    with database.get_connection() as conn:
        show(dict(conn.execute("SELECT * FROM delivery_batches ORDER BY id DESC LIMIT 1").fetchone()))

    section("9. Checked")
    chain = IntegrityLedger.verify_chain()
    print(f"event chain valid: {chain.is_valid} ({chain.total_records} record(s))")
    delivery = DeliveryLedger.verify()
    print(f"delivery ledger valid: {delivery['is_valid']} ({delivery['batches']} batch(es))")


if __name__ == "__main__":
    main()
