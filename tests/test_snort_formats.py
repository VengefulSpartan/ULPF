"""
Snort writes an alert in whichever shape its output plugin was configured for, and a SOC inherits
that choice from whoever set the sensor up. These are the five shapes, written to Snort's own
documented formats, and what the pack must make of each.

The rule that matters most is in test_full_format_header_records_the_alert_without_inventing_endpoints:
in the full format the addresses sit on a later line of the block, and TRACELOG does not hold state
across a stream to stitch them together. A finding without endpoints is right; a finding wearing the
previous alert's addresses is the kind of wrong field this project refuses to produce.
"""
import pytest

from backend.services.normalization.ocsf_export import to_ocsf, validate
from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
from backend.services.parsing.dispatch import parse_log

CSV = ('09/04-21:45:37.536335 ,1,1000006,0,"TCP connection",TCP,10.100.20.59,57263,10.100.10.190,22,'
       '00:25:90:3A:05:13,00:50:56:9D:A5:BE,0x72,***AP***,0x688F0DFC,0xBC763516,,0x80C,127,0,55665,100,102400,,,,')
CSV_ICMP = ('09/04-21:49:55.900215 ,1,1000004,0,"Pinging...",ICMP,10.100.10.190,,175.16.199.1,,'
            '00:50:56:9D:A5:BE,00:25:90:3A:05:13,0x62,,,,,,64,0,37607,84,86016,8,0,83,1')
CSV_PFSENSE = ('09/03/21-12:37:16.428952 ,1,2403488,68499,"ET CINS Active Threat Intelligence Poor Reputation '
               'IP TCP group 95",TCP,203.0.113.7,36847,198.51.100.22,91,54321,Misc Attack,2,alert,Allow')
JSON3 = ('{"seconds":1608147213,"action":"allow","class":"Attempted Administrator Privilege Gain",'
         '"b64_data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","dir":"C2S","dst_addr":"10.11.21.11",'
         '"dst_ap":"10.11.21.11:445","dst_port":445,"gid":1,"msg":"OS-WINDOWS raw WriteAndX attempt",'
         '"pkt_gen":"stream_tcp","pkt_num":61571,"priority":1,"proto":"TCP","rev":1,"rule":"1:50626:1",'
         '"service":"netbios-ssn","sid":50626,"src_addr":"10.11.21.101","src_port":50084,'
         '"timestamp":"12/16-20:33:33.603502"}')
FULL_HEADER = "[**] [1:1000006:0] TCP connection [**]"
FULL_PACKET = "09/04-21:42:42.860730 10.100.20.59:57263 -> 10.100.10.190:22"
FAST = ('05/30-19:09:28.472094  [**] [1:2012811:2] ET DNS DNS Query to a .tk domain - Likely Hostile [**] '
        '[Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 192.168.88.10:1029 -> 203.0.113.53:53')
SYSLOG = ("<33>Sep  5 16:05:26 dev snort: [1:1000017:0] UDP Connection [Classification: Misc activity] "
          "[Priority: 3] {UDP} 10.150.10.44:55776 -> 10.25.10.22:32414")


def snort(line):
    fmt, parsed = parse_log(line)
    assert fmt == "snort_alert", f"no Snort pack claimed this line, {fmt} did"
    return parsed


def test_alert_csv_reads_the_rule_the_message_and_the_endpoints():
    p = snort(CSV)
    assert p["signature"] == "TCP connection" and p["rule_id"] == "1:1000006:0"
    assert (p["src_ip"], p["src_port"]) == ("10.100.20.59", 57263)
    assert (p["dst_ip"], p["dst_port"]) == ("10.100.10.190", 22)
    assert p["proto"] == "tcp" and p["timestamp"].endswith("+00:00")
    assert p["vendor_fields"]["snort_format"] == "csv" and p["vendor_fields"]["ttl"] == "127"


def test_alert_csv_leaves_the_ports_of_a_protocol_that_has_none_empty():
    p = snort(CSV_ICMP)
    assert p["src_ip"] == "10.100.10.190" and p["dst_ip"] == "175.16.199.1"
    assert "src_port" not in p and "dst_port" not in p     # ICMP: the columns are empty, so the fields are


def test_the_csv_pfsense_writes_has_its_own_columns_and_is_read_as_such():
    p = snort(CSV_PFSENSE)
    assert p["rule_id"] == "1:2403488:68499" and p["src_ip"] == "203.0.113.7" and p["dst_port"] == 91
    assert p["threat_type"] == "Misc Attack"                # pfSense writes the classification here
    assert p["severity"] == "medium"                        # priority 2
    assert p["timestamp"].startswith("2021-09-03T12:37:16")  # the two-digit year is read, not the current one


def test_snort_3_json_is_read_without_carrying_the_packet_payload():
    p = snort(JSON3)
    assert p["signature"] == "OS-WINDOWS raw WriteAndX attempt" and p["rule_id"] == "1:50626:1"
    assert (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"]) == ("10.11.21.101", 50084, "10.11.21.11", 445)
    assert p["severity"] == "high" and p["threat_type"].startswith("Attempted Administrator")
    assert p["app_protocol"] == "netbios-ssn"
    assert p["timestamp"].startswith("2020-12-16")          # from "seconds", which carries a year
    assert "b64_data" not in p["vendor_fields"], "the base64 packet would be megabytes per batch"


def test_full_format_header_records_the_alert_without_inventing_endpoints():
    p = snort(FULL_HEADER)
    assert p["signature"] == "TCP connection" and p["rule_id"] == "1:1000006:0"
    assert not any(k in p for k in ("src_ip", "dst_ip", "src_port", "dst_port"))

    # the addresses arrive on the next line of the block, and are read there on their own evidence
    fmt, packet = parse_log(FULL_PACKET)
    assert fmt == "generic_inferred"
    assert packet["src_ip"] == "10.100.20.59" and packet["dst_port"] == 22
    assert "signature" not in packet


def test_the_fast_and_syslog_forms_still_read_as_they_did():
    fast = snort(FAST)
    assert fast["rule_id"] == "1:2012811:2" and fast["dst_port"] == 53 and fast["severity"] == "medium"
    sysl = snort(SYSLOG)
    assert sysl["rule_id"] == "1:1000017:0" and sysl["src_port"] == 55776 and sysl["threat_type"] == "Misc activity"


@pytest.mark.parametrize("line", [CSV, CSV_ICMP, CSV_PFSENSE, JSON3, FULL_HEADER, FAST, SYSLOG])
def test_every_shape_normalises_to_a_valid_ocsf_detection_finding(line):
    parsed = snort(line)
    event = OCSFNormalizer.normalize(parsed, line, "raw-1", "hash-1").model_dump()
    ocsf = to_ocsf(event)
    assert ocsf["class_uid"] == 2004 and validate(ocsf) == []
