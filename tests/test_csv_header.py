"""
CSV and TSV logs whose first line names the columns. The header decides which column is which,
the evidence rules still decide what a column means, the header line itself is kept, and nothing
changes for lines that have no header.
"""
import pytest

from backend.connectors.config import FileInput
from backend.connectors.inputs.pollers import FileTailInput
from backend.services.ingestion.pipeline import IngestionPipeline, split_upload
from backend.services.ingestion.stream import StreamIngestor
from backend.services.parsing.csvheader import header_of, pairs
from backend.services.parsing.dispatch import parse_log

HEADER = "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action,user"
ROWS = ["2026-09-21T10:00:00Z,10.0.0.5,203.0.113.9,51514,443,tcp,allow,alice",
        "2026-09-21T10:00:01Z,10.0.0.6,203.0.113.10,51515,22,tcp,deny,bob"]
# a firewall GUI export: names with spaces, NAT columns that must not be read as the endpoints
GUI_HEADER = "Receive Time,Type,Source address,Destination address,NAT Source IP,Source Port,Destination Port,Action"
GUI_ROW = "2026/09/21 10:15:02,TRAFFIC,10.20.4.5,198.51.100.7,203.0.113.80,58312,443,allow"


def events(database):
    with database.get_connection() as conn:
        return conn.execute(
            "SELECT n.class_name, n.src_ip, n.dst_ip, n.src_port, n.dst_port, n.action, "
            "json_extract(n.unmapped_json, '$.tracelog_parse.csv_header_row') AS header_row, r.raw_text "
            "FROM normalized_events n JOIN raw_logs r ON r.id = n.raw_id ORDER BY n.sequence_num").fetchall()


@pytest.mark.parametrize("line, delimiter", [(HEADER, ","), (HEADER.replace(",", "\t"), "\t"),
                                             (HEADER.replace(",", ";"), ";"), (GUI_HEADER, ",")])
def test_a_header_is_recognised(line, delimiter):
    header = header_of(line, ROWS[0].replace(",", delimiter) if line != GUI_HEADER else GUI_ROW)
    assert header and header["delimiter"] == delimiter and len(header["columns"]) == 8


@pytest.mark.parametrize("line", [
    ROWS[0],                                   # a data row: addresses, numbers and a time
    "action,user",                             # fewer than three columns
    "src,dst,src",                             # a name used twice
    "src=10.0.0.1,dst=10.0.0.2,act=allow",     # key=value, not a header
    '{"src":"a","dst":"b","act":"c"}',         # JSON
    "CEF:0|Vendor|Product|1.0|100|name|5|src=10.0.0.1",
    # Cisco FTD: comma-separated "Key: value" cells, the same count on every line (the layout of
    # Elastic's real FTD sample logs, which an earlier version of this check took for headers)
    "Aug 14 2019 14:54:25 siem-ftd  %FTD-1-430004: SrcIP: 10.0.1.20, DstIP: 10.0.100.30, SrcPort: 41522, "
    "DstPort: 8000, Protocol: tcp",
    "2023-03-27T08:41:37Z   %FTD-1-430003: EventPriority: Low, DeviceUUID: 48a00000, InstanceID: 2",
])
def test_other_lines_are_not_headers(line):
    assert header_of(line, ROWS[0]) is None


def test_a_header_needs_a_next_line_with_the_same_columns_and_a_value():
    assert header_of(HEADER, "only,two") is None
    assert header_of("action,user,host", "allow,bob,web") is None   # nothing shows the first line is names
    assert header_of("action,user,host,port", "allow,bob,web,443")


def test_rows_are_read_by_column_name():
    header = header_of(HEADER, ROWS[0])
    fmt, parsed = parse_log(ROWS[0], header)
    assert fmt == "generic_inferred"
    assert (parsed["src_ip"], parsed["dst_ip"], parsed["src_port"], parsed["dst_port"]) == \
           ("10.0.0.5", "203.0.113.9", 51514, 443)
    assert parsed["tracelog_parse"]["verified"] is False  # names still go through the evidence rules
    assert parsed["tracelog_parse"]["template"].startswith("csv (',') keys: timestamp, src_ip")


def test_without_the_header_the_same_row_gets_no_endpoints():
    _, parsed = parse_log(ROWS[0])
    assert "src_ip" not in parsed and "dst_ip" not in parsed


def test_nat_columns_are_not_taken_for_the_endpoints():
    _, parsed = parse_log(GUI_ROW, header_of(GUI_HEADER, GUI_ROW))
    assert (parsed["src_ip"], parsed["dst_ip"], parsed["dst_port"]) == ("10.20.4.5", "198.51.100.7", 443)


def test_names_that_do_not_say_which_side_assign_nothing():
    header = header_of("time,ip_a,ip_b,port", "2026-09-21T10:00:00Z,10.0.0.1,10.0.0.2,443")
    _, parsed = parse_log("2026-09-21T10:00:00Z,10.0.0.1,10.0.0.2,443", header)
    assert "src_ip" not in parsed and "dst_ip" not in parsed


def test_a_row_with_other_columns_is_parsed_as_before():
    header = header_of(HEADER, ROWS[0])
    assert pairs("a,b,c", header) is None
    assert parse_log("a,b,c", header) == parse_log("a,b,c")


def test_an_upload_keeps_the_header_line_and_reads_the_rows_by_name(isolated_db):
    content = ("\n".join([HEADER] + ROWS) + "\n").encode()
    result = IngestionPipeline.ingest_batch(split_upload(content), source_id=_source(isolated_db),
                                            transport="upload")
    rows = events(isolated_db)
    assert result["ingested"] == 3 and len(rows) == 3          # the header is archived and chained too
    head, first, second = rows
    assert head["header_row"] == 1 and head["class_name"] == "Base Event" and head["raw_text"] == HEADER
    assert (first["class_name"], first["src_ip"], first["dst_ip"], first["dst_port"]) == \
           ("Network Activity", "10.0.0.5", "203.0.113.9", 443)
    assert (second["src_ip"], second["dst_port"], second["action"]) == ("10.0.0.6", 22, "deny")
    with isolated_db.get_connection() as conn:
        templates = [r[0] for r in conn.execute("SELECT template FROM log_formats")]
    assert templates and all(t.startswith("csv (") for t in templates)  # the header is not a "new format"


def test_a_tailed_file_uses_its_header_also_after_a_restart(isolated_db, tmp_path):
    log = tmp_path / "export.csv"
    log.write_text(HEADER + "\n" + ROWS[0] + "\n")
    cfg = FileInput(name="csv-export", paths=[str(log)], start_at="beginning")
    ingest = StreamIngestor().ingest
    FileTailInput(cfg, ingest, str(tmp_path / "state")).poll_once()
    with log.open("a") as fh:
        fh.write(ROWS[1] + "\n")
    FileTailInput(cfg, ingest, str(tmp_path / "state")).poll_once()   # a new process resumes mid-file
    rows = events(isolated_db)
    assert [r["header_row"] for r in rows] == [1, None, None]
    assert [r["src_ip"] for r in rows] == [None, "10.0.0.5", "10.0.0.6"]


def _source(database):
    with database.get_connection() as conn:
        conn.execute("INSERT INTO sources (id, name, vendor, product, format_type, category, created_at) "
                     "VALUES ('src-csv', 'CSV export', 'Generic', 'CSV', 'csv', 'firewall', datetime('now'))")
        conn.commit()
    return "src-csv"
