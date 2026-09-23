"""
Key/value pairs from one XML log event, so XML is read by the same evidence rules as JSON.

The PS names XML among the formats a universal framework has to take. Devices and agents write it
in two layouts, and both are read:

  element per field      <log><src>10.1.1.5</src><dport>443</dport></log>
                         -> ("src", "10.1.1.5"), ("dport", "443")
  named data elements    <EventData><Data Name="IpAddress">203.0.113.7</Data></EventData>
                         -> ("EventData.IpAddress", "203.0.113.7")    (Windows events, and many others)

Paths join element names with dots and leave out the root, the way nested JSON keys are joined;
attributes become the element's path plus the attribute name (<TimeCreated SystemTime="..."/> ->
"TimeCreated.SystemTime"); namespaces are dropped from names.

A log event has no use for a DOCTYPE or entity declarations, and they are how XML parsers are made
to expand entities without end or fetch files, so a document carrying either is not parsed as XML
at all — it stays a text line, archived like any other. Documents over MAX_BYTES are left alone for
the same reason.
"""
import re
import xml.etree.ElementTree as ET
from typing import Any, List, Optional, Tuple

MAX_BYTES = 64 * 1024
MAX_PAIRS = 400
_LOOKS_XML = re.compile(r"^(?:<\?xml[^>]*\?>\s*)?<([A-Za-z_][\w.:-]*)[\s>/]", re.S)
_REFUSED = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.I)


def _local(name: str) -> str:
    """'{http://schemas...}EventID' and 'ns:EventID' -> 'EventID'."""
    if "}" in name:
        name = name.rsplit("}", 1)[1]
    return name.rsplit(":", 1)[-1]


def looks_like_xml(text: str) -> bool:
    b = text.strip()
    return b.endswith(">") and bool(_LOOKS_XML.match(b))


def xml_pairs(text: str) -> Optional[List[Tuple[str, Any]]]:
    """The event's (key, value) pairs, or None when this is not XML TRACELOG will read."""
    b = text.strip()
    if len(b) > MAX_BYTES or not looks_like_xml(b) or _REFUSED.search(b):
        return None
    try:
        root = ET.fromstring(b)
    except ET.ParseError:
        return None
    pairs: List[Tuple[str, Any]] = []

    def join(parent: str, name: str) -> str:
        return f"{parent}.{name}" if parent else name

    def walk(el: ET.Element, parent: str, is_root: bool) -> None:
        if len(pairs) >= MAX_PAIRS:
            return
        text_value = (el.text or "").strip()
        named = el.attrib.get("Name", el.attrib.get("name"))
        if is_root:
            path = ""
        elif named is not None and text_value:
            path = join(parent, named)          # <Data Name="X">v</Data>: the name is the key
        else:
            path = join(parent, _local(el.tag))
        for attr, value in el.attrib.items():
            local = _local(attr)
            if named is not None and text_value and local.lower() == "name":
                continue                         # already the key
            pairs.append((join(path, local) if path else local, value.strip()))
        children = list(el)
        if text_value and (not is_root or not children):
            pairs.append((path or _local(el.tag), text_value))
        for child in children:
            walk(child, path, False)

    walk(root, "", True)
    return pairs or None
