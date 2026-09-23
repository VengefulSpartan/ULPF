"""
The Parquet output must satisfy what Amazon Security Lake requires of a custom source, because
"Security Lake ready" is either true of the objects on disk or it is a slogan:

  ext/<source>/region=<region>/accountId=<id>/eventDay=<YYYYMMDD>/   the partition keys, in order
  one OCSF event class per object                                    not one file holding several
  zstd                                                               the compression AWS expects
  rows ordered by time                                               asked for, and cheaper to query
  OCSF 1.3 or earlier                                                what the lake can read

The default layout is unchanged, so an existing deployment keeps its class_uid/event_day tree.
"""
import re

import pytest

from backend.connectors.config import Output
from backend.connectors.outputs.base import DeliveryError
from backend.connectors.outputs.file_sinks import ParquetSink

pytest.importorskip("pyarrow")
import pyarrow.parquet as pq          # noqa: E402

SECURITY_LAKE_PATH = re.compile(
    r"ext/tracelog/region=ap-south-1/accountId=external/eventDay=(\d{8})/class_uid=(\d+)-[^/]+\.parquet$")


def events():
    """Three classes, two days, deliberately out of time order."""
    base = 1789912815000                                   # 2026-09-20T14:00:15Z
    day = 24 * 60 * 60 * 1000
    return [
        {"class_uid": 4001, "class_name": "Network Activity", "time": base + 5000,
         "metadata": {"version": "1.1.0", "product": {"vendor_name": "Cisco", "name": "ASA"}}},
        {"class_uid": 4001, "class_name": "Network Activity", "time": base + 1000,
         "metadata": {"version": "1.1.0", "product": {"vendor_name": "Cisco", "name": "ASA"}}},
        {"class_uid": 3002, "class_name": "Authentication", "time": base + 3000,
         "metadata": {"version": "1.1.0", "product": {"vendor_name": "Fortinet", "name": "FortiGate"}}},
        {"class_uid": 2004, "class_name": "Detection Finding", "time": base + day,
         "metadata": {"version": "1.1.0", "product": {"vendor_name": "Suricata", "name": "Suricata"}}},
    ]


def sink(tmp_path, **settings):
    settings.setdefault("root", str(tmp_path / "lake"))
    return ParquetSink(Output(name="lake", type="parquet", settings=settings), data_dir=str(tmp_path))


def test_security_lake_partitions_and_one_class_per_object(tmp_path):
    s = sink(tmp_path, layout="security_lake", region="ap-south-1")
    s.send(events())

    files = sorted((tmp_path / "lake").rglob("*.parquet"))
    assert len(files) == 3                                    # 4001 and 3002 on day one, 2004 on day two
    for path in files:
        match = SECURITY_LAKE_PATH.search(str(path))
        assert match, f"{path} is not laid out the way Security Lake reads"
        day, class_in_name = match.groups()
        table = pq.read_table(path)
        classes = set(table.column("class_uid").to_pylist())
        assert classes == {int(class_in_name)}, "one OCSF event class per object"
        assert all(f"{d:%Y%m%d}" == day for d in
                   (__import__("datetime").datetime.fromtimestamp(t / 1000, __import__("datetime").timezone.utc)
                    for t in table.column("time").to_pylist())), "eventDay must be the event's own UTC day"

    assert {p.parent.name for p in files} == {"eventDay=20260920", "eventDay=20260921"}


def test_rows_are_ordered_by_time_and_compressed_with_zstd(tmp_path):
    s = sink(tmp_path, layout="security_lake", region="ap-south-1")
    s.send(events())
    network = next(p for p in (tmp_path / "lake").rglob("*.parquet") if "class_uid=4001" in p.name)

    table = pq.read_table(network)
    times = table.column("time").to_pylist()
    assert times == sorted(times) and len(times) == 2

    meta = pq.ParquetFile(network).metadata.row_group(0)
    assert {meta.column(i).compression for i in range(meta.num_columns)} == {"ZSTD"}


def test_the_default_layout_is_unchanged(tmp_path):
    s = sink(tmp_path)
    assert s.describe_target().endswith("class_uid=*/event_day=*/*.parquet")
    s.send(events())
    files = list((tmp_path / "lake").rglob("*.parquet"))
    assert len(files) == 3
    assert all(re.search(r"class_uid=\d+/event_day=\d{8}/part-[^/]+\.parquet$", str(p)) for p in files)


def test_a_security_lake_output_refuses_settings_it_cannot_honour(tmp_path):
    with pytest.raises(ValueError, match="region"):
        sink(tmp_path, layout="security_lake")                       # no region: nothing to guess from
    with pytest.raises(ValueError, match="zstd"):
        sink(tmp_path, layout="security_lake", region="ap-south-1", compression="snappy")
    with pytest.raises(ValueError, match="layout"):
        sink(tmp_path, layout="delta")


def test_events_from_a_newer_ocsf_than_the_lake_reads_are_not_written(tmp_path):
    s = sink(tmp_path, layout="security_lake", region="ap-south-1")
    future = events()
    for e in future:
        e["metadata"]["version"] = "1.9.0"
    with pytest.raises(DeliveryError, match="1.3"):
        s.send(future)
    assert not list((tmp_path / "lake").rglob("*.parquet"))
