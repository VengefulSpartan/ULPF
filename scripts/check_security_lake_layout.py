"""
Check that a Parquet output really is laid out the way Amazon Security Lake reads a custom source.

    python scripts/check_security_lake_layout.py data/lake

Walks every .parquet file under the given root and verifies, per AWS's custom-source requirements:

  path          ext/<source>/region=<region>/accountId=<id>/eventDay=<YYYYMMDD>/<file>.parquet
  one class     each object holds exactly one OCSF class_uid
  eventDay      matches the UTC day of every event time inside the file
  compression   zstd
  ordering      rows sorted by time
  schema        OCSF 1.3 or earlier
  sizes         data pages under 1 MB, row groups under 256 MB compressed

Exit status is 0 when everything passes, 1 otherwise, so it can gate a release. Copying the tree
into the bucket is `aws s3 sync <root> s3://<bucket>/` — TRACELOG writes files, not S3 objects,
which is what lets this output work air-gapped.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

PATH_PARTS = ("ext", "region=", "accountId=", "eventDay=")
MAX_PAGE_BYTES = 1024 * 1024
MAX_ROW_GROUP_BYTES = 256 * 1024 * 1024
MAX_OCSF = (1, 3)


def problems_with(path: Path, root: Path):
    import pyarrow.parquet as pq

    out = []
    rel = path.relative_to(root).as_posix()
    parts = rel.split("/")
    if len(parts) < 5 or parts[0] != "ext" or not parts[2].startswith("region=") \
            or not parts[3].startswith("accountId=") or not parts[4].startswith("eventDay="):
        return [f"path is not ext/<source>/region=/accountId=/eventDay=/<file>: {rel}"]
    day = parts[4].split("=", 1)[1]
    if len(day) != 8 or not day.isdigit():
        out.append(f"eventDay must be YYYYMMDD, found {day!r}")

    f = pq.ParquetFile(path)
    table = f.read()
    classes = set(table.column("class_uid").to_pylist()) if "class_uid" in table.column_names else set()
    if len(classes) != 1:
        out.append(f"holds {len(classes)} OCSF classes; Security Lake wants one per object")

    times = table.column("time").to_pylist() if "time" in table.column_names else []
    if times != sorted(t or 0 for t in times):
        out.append("rows are not ordered by time")
    for t in times:
        if t and f"{datetime.fromtimestamp(t / 1000, timezone.utc):%Y%m%d}" != day:
            out.append(f"an event timed {t} is not in eventDay={day}")
            break

    if "ocsf" in table.column_names and table.num_rows:
        import json
        version = str((json.loads(table.column("ocsf")[0].as_py()).get("metadata") or {}).get("version") or "")
        try:
            if version and tuple(int(n) for n in version.split(".")[:2]) > MAX_OCSF:
                out.append(f"events say OCSF {version}; the lake reads 1.3 and earlier")
        except ValueError:
            out.append(f"unreadable OCSF version {version!r}")

    for g in range(f.metadata.num_row_groups):
        group = f.metadata.row_group(g)
        if group.total_byte_size > MAX_ROW_GROUP_BYTES:
            out.append(f"row group {g} is {group.total_byte_size / 1e6:.0f} MB, over the 256 MB limit")
        for c in range(group.num_columns):
            column = group.column(c)
            if column.compression != "ZSTD":
                out.append(f"column {column.path_in_schema} is {column.compression}, not ZSTD")
                break
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    root = Path(sys.argv[1])
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        print("pyarrow is needed to read the files: pip install pyarrow")
        return 2
    files = sorted(root.rglob("*.parquet"))
    if not files:
        print(f"no .parquet files under {root}")
        return 1
    failed = 0
    for path in files:
        issues = problems_with(path, root)
        if issues:
            failed += 1
            print(f"FAIL {path.relative_to(root)}")
            for issue in issues:
                print(f"     {issue}")
    print(f"\n{len(files) - failed} of {len(files)} objects are laid out for Security Lake")
    if not failed:
        print(f"upload with:  aws s3 sync {root} s3://<your-security-lake-bucket>/")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
