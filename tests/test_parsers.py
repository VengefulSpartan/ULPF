import pytest
from backend.services.parsing.cef_parser import CEFParser
from backend.services.parsing.leef_parser import LEEFParser
from backend.services.parsing.syslog_parser import SyslogParser
from backend.services.parsing.kv_parser import KVParser
from backend.services.parsing.json_parser import JSONParser
from backend.services.parsing.detector import FormatDetector

def test_cef_parser():
    line = 'CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|traffic-start|3|src=192.168.1.10 dst=10.0.0.5 spt=54321 dpt=443 proto=TCP act=allow'
    success, data = CEFParser.parse(line)
    assert success is True
    assert data["vendor"] == "Palo Alto Networks"
    assert data["product"] == "PAN-OS"
    assert data["src"] == "192.168.1.10"
    assert data["dst"] == "10.0.0.5"
    assert data["spt"] == "54321"
    assert data["dpt"] == "443"
    assert data["proto"] == "TCP"
    assert data["act"] == "allow"

def test_leef_parser():
    line = 'LEEF:1.0|Microsoft|MSExchange|2013|15307|src=10.10.10.5\tdst=192.168.1.1\tspt=52000\tdpt=25\tproto=TCP\tusrName=jdoe'
    success, data = LEEFParser.parse(line)
    assert success is True
    assert data["vendor"] == "Microsoft"
    assert data["src"] == "10.10.10.5"
    assert data["usrName"] == "jdoe"

def test_syslog_rfc5424():
    line = '<34>1 2026-09-20T18:00:00.000Z firewall.corp.local su 1234 ID47 [exampleSDID@32473 iut="3"] BOMUser authentication failure'
    success, data = SyslogParser.parse(line)
    assert success is True
    assert data["syslog_standard"] == "RFC5424"
    assert data["pri"] == 34
    assert data["hostname"] == "firewall.corp.local"
    assert data["app_name"] == "su"

def test_syslog_rfc3164_with_cisco_msg():
    line = '<166>Sep 20 18:02:15 ciscoasa %ASA-6-302013: Built outbound TCP connection 123456 for outside:192.168.10.5/443 (192.168.10.5/443) to inside:10.0.1.100/52012'
    success, data = SyslogParser.parse(line)
    assert success is True
    assert data["syslog_standard"] == "RFC3164"
    assert data["hostname"] == "ciscoasa"
    assert data["app_name"] == "%ASA-6-302013"
    assert "Built outbound TCP connection" in data["message"]

def test_kv_parser():
    line = 'date=2026-09-20 time=18:05:00 devname="FGT60D" devid="FGT60D0000000000" type="traffic" action="deny" srcip=192.168.1.50 dstip=8.8.8.8 proto=17 service="DNS"'
    success, data = KVParser.parse(line)
    assert success is True
    assert data["devname"] == "FGT60D"
    assert data["action"] == "deny"
    assert data["srcip"] == "192.168.1.50"
    assert data["service"] == "DNS"

def test_json_parser():
    line = '{"timestamp":"2026-09-20T18:10:00.000000+0000","event_type":"alert","src_ip":"192.168.1.105","src_port":41234,"dest_ip":"10.0.0.1","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature":"ET EXPLOIT Apache Struts RCE"}}'
    success, data = JSONParser.parse(line)
    assert success is True
    assert data["src_ip"] == "192.168.1.105"
    assert data["event_type"] == "alert"
    assert data["alert"]["signature"] == "ET EXPLOIT Apache Struts RCE"

def test_format_detector():
    cef = 'CEF:0|Palo Alto|PAN-OS|1.0|1|traffic|1|src=1.1.1.1'
    fmt, _ = FormatDetector.detect_and_parse(cef)
    assert fmt == "cef"

    json_str = '{"src_ip": "1.1.1.1", "action": "allow"}'
    fmt, _ = FormatDetector.detect_and_parse(json_str)
    assert fmt == "json"

    kv_str = 'src=1.1.1.1 dst=2.2.2.2 act=drop'
    fmt, _ = FormatDetector.detect_and_parse(kv_str)
    assert fmt == "kv"
