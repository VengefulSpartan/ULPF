"""
Cisco ASA/FTD Teardown messages do not say which end opened the connection; the Built
message for the same connection does. These tests pin down that a Teardown takes its
direction from its own Built message, and that without one it assigns nothing rather
than guessing. Found by scoring real ASA sample logs: reading the first address as the
source turned every outbound DNS lookup's teardown into "from 192.168.80.32 port 53".
"""
import pytest

from backend.services.normalization.ocsf_export import to_ocsf, validate
from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
from backend.services.parsing.dispatch import parse_log
from backend.services.vendors import cisco


@pytest.fixture(autouse=True)
def fresh_connections():
    cisco.OPEN_CONNECTIONS.clear()
    yield
    cisco.OPEN_CONNECTIONS.clear()


def ends(line):
    _, parsed = parse_log(line)
    ev = OCSFNormalizer.normalize(parsed, line, "raw", "hash").model_dump()
    src, dst = ev.get("src_endpoint") or {}, ev.get("dst_endpoint") or {}
    return ev, (src.get("ip"), src.get("port")), (dst.get("ip"), dst.get("port"))


HEAD = "<166>Oct 10 2018 12:34:56 {host} : "
BUILT_DNS = HEAD + ("%ASA-6-302015: Built outbound UDP connection 11758 for outside:192.0.2.32/53 (192.0.2.32/53) "
                    "to inside:10.31.98.44/56132 (10.31.98.44/56132)")
TEARDOWN_DNS = HEAD + ("%ASA-6-302016: Teardown UDP connection 11758 for outside:192.0.2.32/53 to "
                       "inside:10.31.98.44/56132 duration 0:00:00 bytes 148")
BUILT_WEB_IN = HEAD + ("%ASA-6-302013: Built inbound TCP connection 900 for outside:198.51.100.22/51200 "
                       "(198.51.100.22/51200) to dmz:10.0.1.15/443 (203.0.113.15/443)")
TEARDOWN_WEB_IN = HEAD + ("%ASA-6-302014: Teardown TCP connection 900 for outside:198.51.100.22/51200 to "
                          "dmz:10.0.1.15/443 duration 0:00:05 bytes 5120 TCP FINs")
BUILT_PING = HEAD + ("%ASA-6-302020: Built outbound ICMP connection for faddr 198.51.100.8/0 gaddr 203.0.113.4/7 "
                     "laddr 10.0.0.4/7")
TEARDOWN_PING = HEAD + ("%ASA-6-302021: Teardown ICMP connection for faddr 198.51.100.8/0 gaddr 203.0.113.4/7 "
                        "laddr 10.0.0.4/7")


def test_outbound_teardown_takes_direction_from_its_built_message():
    ends(BUILT_DNS.format(host="asa01"))
    ev, src, dst = ends(TEARDOWN_DNS.format(host="asa01"))
    assert src == ("10.31.98.44", 56132) and dst == ("192.0.2.32", 53)
    assert ev["unmapped"]["vendor_fields"]["direction_source"] == "built message"


def test_inbound_teardown_keeps_the_outside_end_as_source():
    ends(BUILT_WEB_IN.format(host="asa01"))
    _, src, dst = ends(TEARDOWN_WEB_IN.format(host="asa01"))
    assert src == ("198.51.100.22", 51200) and dst == ("10.0.1.15", 443)


def test_teardown_without_its_built_message_assigns_nothing_and_keeps_both_ends():
    ev, src, dst = ends(TEARDOWN_DNS.format(host="asa01"))
    assert src == (None, None) and dst == (None, None)
    unmapped = ev["unmapped"]["vendor_fields"]
    assert (unmapped["fip"], unmapped["fport"], unmapped["tip"], unmapped["tport"]) == \
           ("192.0.2.32", "53", "10.31.98.44", "56132")
    assert unmapped["direction_source"] == "not seen"
    assert ev["class_uid"] == 4001 and validate(to_ocsf(ev)) == []


def test_connection_ids_are_per_device():
    ends(BUILT_DNS.format(host="asa01"))
    _, src, _ = ends(TEARDOWN_DNS.format(host="asa02"))
    assert src == (None, None)


def test_a_connection_is_torn_down_once():
    ends(BUILT_DNS.format(host="asa01"))
    ends(TEARDOWN_DNS.format(host="asa01"))
    assert len(cisco.OPEN_CONNECTIONS) == 0
    _, src, _ = ends(TEARDOWN_DNS.format(host="asa01"))
    assert src == (None, None)


def test_icmp_teardown_takes_direction_from_its_built_message():
    _, src, dst = ends(BUILT_PING.format(host="asa01"))
    assert src[0] == "10.0.0.4" and dst[0] == "198.51.100.8"
    _, src, dst = ends(TEARDOWN_PING.format(host="asa01"))
    assert src[0] == "10.0.0.4" and dst[0] == "198.51.100.8"


def test_icmp_teardown_without_built_assigns_nothing():
    _, src, dst = ends(TEARDOWN_PING.format(host="asa01"))
    assert src == (None, None) and dst == (None, None)


def test_memory_is_bounded():
    table = cisco._OpenConnections(limit=3)
    for cid in range(5):
        table.remember(("asa01", str(cid)), ("a", "1", "b", "2"), "outbound")
    assert len(table) == 3
    assert table.take(("asa01", "0"), ("a", "1", "b", "2")) is None
    assert table.take(("asa01", "4"), ("a", "1", "b", "2")) == "outbound"


def test_a_reused_connection_id_with_other_ends_is_not_joined():
    # two devices that send no hostname can reuse a connection id; the ends must match too
    ends(BUILT_DNS.format(host="asa01"))
    other = TEARDOWN_WEB_IN.format(host="asa01").replace("connection 900", "connection 11758")
    _, src, dst = ends(other)
    assert src == (None, None) and dst == (None, None)


def test_an_object_name_in_place_of_an_address_is_the_endpoint_hostname():
    # ASA with "names" configured; line from Cisco's own message layout
    line = ("Dec 11 2018 08:01:31 127.0.0.1: %FTD-6-302013: Built outbound TCP connection 447236 for "
            "outside:192.0.2.222/1234 (192.0.2.222/1234) to dmz:OCSP_Server/5678 (OCSP_Server/5678)")
    _, parsed = parse_log(line)
    ev = OCSFNormalizer.normalize(parsed, line, "raw", "hash").model_dump()
    assert ev["src_endpoint"] == {"ip": None, "port": 5678, "hostname": "OCSP_Server", "mac": None}
    assert ev["dst_endpoint"]["ip"] == "192.0.2.222" and ev["dst_endpoint"]["port"] == 1234
    assert "tracelog_value_checks" not in parsed and validate(to_ocsf(ev)) == []
