"""
Formats TRACELOG has no parser for must never produce wrong fields: what the fallback
fills has to be right, and it has to say why and how sure it is.
"""
import pytest

from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
from backend.services.parsing.dispatch import parse_log
from backend.services.vendors.envelope import split_envelope
from tests.test_vendor_packs import ASA_DENY, FORTI_TRAFFIC
from tests.unseen_corpus import CORPUS, PAN_TRAFFIC_DRIFTED, score


def normalized(line):
    fmt, parsed = parse_log(line)
    ev = OCSFNormalizer.normalize(parsed, line, "r", "h", vendor=parsed.get("vendor") or "Generic",
                                  product=parsed.get("product") or "Device").model_dump()
    return fmt, parsed, ev


@pytest.mark.parametrize("case", CORPUS, ids=[c["name"] for c in CORPUS])
def test_no_wrong_fields_on_unseen_formats(case):
    _, _, ev = normalized(case["line"])
    wrong, missed, correct = score(ev, case["truth"])
    assert wrong == [], f"{case['name']}: {wrong}"


def test_most_fields_are_still_found():
    totals = [score(normalized(c["line"])[2], c["truth"]) for c in CORPUS]
    correct = sum(len(t[2]) for t in totals)
    fields = sum(len(t[0]) + len(t[1]) + len(t[2]) for t in totals)
    assert correct / fields >= 0.75, f"{correct}/{fields}"


def test_every_filled_field_says_why_and_how_sure():
    _, parsed, ev = normalized(CORPUS[4]["line"])  # F5 BIG-IP ASM
    tp = ev["unmapped"]["tracelog_parse"]
    assert tp["verified"] is False and 0.7 <= tp["confidence"] <= 1
    assert "ip_client" in tp["fields"]["src_ip"]["why"] and tp["fields"]["src_ip"]["value"] == "203.0.113.9"
    assert tp["fields"]["action"]["value"] == "denied" and tp["fields"]["signature"]["value"] == "SQL-Injection"
    assert ev["class_uid"] == 2004


def test_syslog_severity_is_not_inverted():
    # <134> = facility local0, severity 6 (informational): it used to come out as Critical
    _, _, ev = normalized("<134>Sep 21 10:00:00 edge-rtr something happened on the router")
    assert ev["severity"] == "Informational"
    _, _, ev = normalized("<130>Sep 21 10:00:00 edge-rtr power supply failed")  # severity 2 = critical
    assert ev["severity"] == "Critical"


def test_rfc5424_header_does_not_swallow_message_fields():
    env = split_envelope("<134>1 1789984800.123 MX84 flows src=10.0.0.5 dst=8.8.8.8 sport=1 dport=53")
    assert env.hostname == "MX84" and env.app == "flows" and env.message.startswith("src=10.0.0.5 dst=8.8.8.8")
    ok = split_envelope('<14>1 2026-09-21T10:45:00Z srx01 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636 a="1"] x')
    assert ok.app == "RT_FLOW" and ok.msgid == "RT_FLOW_SESSION_DENY" and ok.sd


def test_arrival_time_is_never_passed_off_as_device_time():
    _, _, ev = normalized("2 123456789012 eni-0a1b2c3d 203.0.113.12 10.0.1.5 49761 22 6 20 4249 x y REJECT OK")
    assert ev["unmapped"]["time_source"] == "received"
    _, _, ev = normalized(CORPUS[0]["line"])  # Huawei: time=2026/9/21 10:00:00
    assert "time_source" not in ev["unmapped"] and ev["time"].startswith("2026-09-21T10:00:00")


def test_two_ips_without_direction_are_not_assigned():
    _, parsed, ev = normalized(CORPUS[6]["line"])  # WatchGuard: positional, no source/destination marker
    assert ev["src_endpoint"]["ip"] is None and ev["dst_endpoint"]["ip"] is None
    assert set(parsed["tracelog_parse"]["unassigned_ips"]) == {"10.0.1.5", "203.0.113.9"}


def test_a_drifted_positional_format_is_not_passed_on_misaligned():
    fmt, parsed, ev = normalized(PAN_TRAFFIC_DRIFTED)
    assert fmt == "generic_inferred"
    drift = parsed["tracelog_parse"]["pack_drift"]
    assert drift["pack"] == "paloalto_panos" and any("NEWCOL" in p for p in drift["problems"])
    assert ev["src_endpoint"]["ip"] is None  # rather than 'NEWCOL'


def test_one_impossible_value_is_dropped_but_the_pack_is_kept():
    line = FORTI_TRAFFIC.replace("srcip=10.1.1.20", "srcip=ATTACKER-HOST")
    fmt, parsed, ev = normalized(line)
    assert fmt == "fortinet_fortigate" and ev["dst_endpoint"]["ip"] == "198.51.100.25"
    assert ev["src_endpoint"]["ip"] is None
    assert parsed["vendor_fields"]["src_ip_rejected"] == "ATTACKER-HOST"
    assert "not an IP address" in parsed["tracelog_value_checks"][0]


def test_an_asa_object_name_is_a_hostname_not_a_bad_address():
    # the ASA writes a configured object name where the address would be ("names" command)
    line = ASA_DENY.replace("outside:203.0.113.77/40111", "outside:ATTACKER-HOST/40111")
    fmt, parsed, ev = normalized(line)
    assert fmt == "cisco_asa" and ev["dst_endpoint"]["ip"] == "10.0.0.20"
    assert ev["src_endpoint"]["ip"] is None and ev["src_endpoint"]["hostname"] == "ATTACKER-HOST"
    assert ev["src_endpoint"]["port"] == 40111 and "tracelog_value_checks" not in parsed


def test_known_vendor_packs_are_untouched():
    from tests.test_vendor_packs import FORTI_TRAFFIC, PAN_TRAFFIC, SURICATA
    for line, pack in ((PAN_TRAFFIC, "paloalto_panos"), (FORTI_TRAFFIC, "fortinet_fortigate"),
                       (SURICATA, "suricata_eve")):
        fmt, parsed, _ = normalized(line)
        assert fmt == pack and "tracelog_parse" not in parsed
