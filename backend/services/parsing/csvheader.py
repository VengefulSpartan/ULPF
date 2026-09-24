"""
CSV and TSV logs whose first line names the columns.

A CSV line on its own does not say what its columns are; the file's header row often does
("timestamp,src_ip,dst_ip,dst_port,action", or a firewall GUI export's "Receive Time,...,Source
address,Destination address,..."). When the header is known, each data line is read as
(column name, value) pairs and goes through the same evidence rules as key=value logs: a column
becomes the source address only if its name says so and its value is a valid address. The header
line itself is archived, hashed and chained like any other line; it is marked as the header and
is not counted as a new log format.

Where a header can be known: an uploaded file or a submitted batch (its first line) and a tailed
file (the first line of the file, read again after a restart). A stream — syslog, Kafka, HTTP —
carries no header, so nothing changes there.
"""
import csv
import re
from typing import Any, Dict, List, Optional, Tuple

from backend.services.parsing.inference import as_ip, as_time

DELIMITERS = (",", "\t", ";")
MIN_COLUMNS = 3
MAX_NAME = 64
_NUMBER = re.compile(r"^[+-]?\d+(?:[.:]\d+)*$")
_NAME = re.compile(r"[A-Za-z]")
# a value inside a cell: an IPv4 address, a run of three digits, "key: value" or "key=value".
# Cisco FTD writes "SrcIP: 10.0.1.20, DstIP: ..., SrcPort: 41522": comma-separated, the same
# number of cells on every line, and not a header.
_EMBEDDED_VALUE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}|\d{3,}|:\s|=")
BOM = "\ufeff"

Header = Dict[str, Any]   # {"delimiter": ",", "columns": [...]}


def split(line: str, delimiter: str) -> List[str]:
    """Cells of one line, honouring quotes the way CSV writers produce them."""
    try:
        return [c.strip() for c in next(csv.reader([line], delimiter=delimiter))]
    except (csv.Error, StopIteration):
        return []


def _is_value(cell: str) -> bool:
    return bool(as_ip(cell) or _NUMBER.match(cell) or as_time(cell))


def _is_name(cell: str) -> bool:
    return bool(cell and len(cell) <= MAX_NAME and _NAME.search(cell) and not _is_value(cell)
                and not _EMBEDDED_VALUE.search(cell) and not any(as_ip(t) for t in cell.split()))


def _looks_like_names(cells: List[str]) -> bool:
    if len(cells) < MIN_COLUMNS:
        return False
    if len({c.lower() for c in cells}) != len(cells):
        return False  # a header names each column once
    return all(_is_name(c) for c in cells)


def header_of(first: str, second: Optional[str] = None) -> Optional[Header]:
    """The header, if `first` is one: at least three distinct column names, none of them holding a
    value (an address, a number, a time, "key: value"), and no vendor pack claims the line. When the
    next line is known it must have the same number of columns, at least one of them a value."""
    first = first.strip().lstrip(BOM)
    if not first or first.startswith(("{", "<", "#")) or "CEF:" in first or "LEEF:" in first:
        return None
    from backend.services.vendors import parse_vendor  # late import: the packs import the parsers
    if parse_vendor(first):
        return None
    best: Optional[Header] = None
    for delimiter in DELIMITERS:
        if first.count(delimiter) < MIN_COLUMNS - 1:
            continue
        cells = split(first, delimiter)
        if not _looks_like_names(cells):
            continue
        if second is not None:
            row = split(second.strip(), delimiter)
            if len(row) != len(cells) or not any(_is_value(c) for c in row):
                continue
        if best is None or len(cells) > len(best["columns"]):
            best = {"delimiter": delimiter, "columns": cells}
    return best


def pairs(line: str, header: Header) -> Optional[List[Tuple[str, str]]]:
    """(column, value) pairs for a data line, or None when it does not have the header's columns."""
    cells = split(line.strip(), header["delimiter"])
    if len(cells) != len(header["columns"]):
        return None
    return list(zip(header["columns"], cells))


def hints_for(lines: List[str]) -> List[Dict[str, Any]]:
    """Per-line parsing hints for a file or batch whose lines are given in order: the header row is
    marked, and every later line carries the header. Empty dicts when the first line is no header."""
    hints: List[Dict[str, Any]] = [{} for _ in lines]
    if not lines:
        return hints
    header = header_of(lines[0], lines[1] if len(lines) > 1 else None)
    if header:
        hints[0] = {"csv_header_row": True}
        for h in hints[1:]:
            h["csv_header"] = header
    return hints
