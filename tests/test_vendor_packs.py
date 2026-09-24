"""
Vendor pack tests. Sample lines are written for these tests following each
vendor's documented format (addresses from RFC 5737 / RFC 1918 ranges).
"""
import pytest

from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
from backend.services.parsing.dispatch import parse_log
from backend.services.vendors.envelope import split_envelope


def norm(line):
    fmt, parsed = parse_log(line)
    return fmt, parsed, OCSFNormalizer.normalize(parsed, line, "raw-1", "hash-1")


PAN_TRAFFIC = ("<14>Sep 21 10:15:02 PA-3220 1,2026/09/21 10:15:02,012801096514,TRAFFIC,end,2561,2026/09/21 10:15:01,"
               "10.20.4.5,203.0.113.80,198.51.100.7,203.0.113.80,allow-web,corp\\alice,,ssl,vsys1,trust,untrust,"
               "ethernet1/2,ethernet1/1,fwd-siem,2026/09/21 10:15:01,58312,1,51514,443,24110,443,0x400053,tcp,allow,"
               "9800,1200,8600,22,2026/09/21 10:14:50,11,computer-and-internet-info,0,77441,0x0,10.0.0.0-10.255.255.255,"
               "United States,0,12,10,tcp-fin")
PAN_THREAT = ("1,2026/09/21 10:16:11,012801096514,THREAT,vulnerability,2561,2026/09/21 10:16:10,203.0.113.50,10.20.4.9,"
              "0.0.0.0,0.0.0.0,inbound-dmz,,,web-browsing,vsys1,untrust,dmz,ethernet1/1,ethernet1/3,fwd-siem,"
              "2026/09/21 10:16:10,99121,1,40022,80,0,0,0x2000,tcp,reset-both,\"cgi-bin/test.cgi\","
              "Apache Struts2 Remote Code Execution Vulnerability(33240),any,critical,client-to-server")
FORTI_TRAFFIC = ('<189>date=2026-09-21 time=10:20:00 devname="FGT-HQ" devid="FG100FTK19000001" logid="0000000013" '
                 'type="traffic" subtype="forward" level="notice" vd="root" eventtime=1789986000000000000 tz="+0530" '
                 'srcip=10.1.1.20 srcport=52211 srcintf="port2" dstip=198.51.100.25 dstport=443 dstintf="wan1" '
                 'proto=6 action="deny" policyid=12 service="HTTPS" sentbyte=0 rcvdbyte=0')
FORTI_VPN_FAIL = ('<185>date=2026-09-21 time=10:21:00 devname="FGT-HQ" devid="FG100FTK19000001" logid="0101039426" '
                  'type="event" subtype="vpn" level="alert" vd="root" logdesc="SSL VPN login fail" action="ssl-login-fail" '
                  'tunneltype="ssl-web" remip=203.0.113.99 user="bob" reason="sslvpn_login_permission_denied" '
                  'msg="SSL user failed to logged in"')
FORTI_IPS = ('<190>date=2026-09-21 time=10:22:00 devname="FGT-HQ" devid="FG100FTK19000001" logid="0419016384" '
             'type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" severity="critical" '
             'srcip=203.0.113.44 dstip=10.1.1.30 srcport=41000 dstport=445 proto=6 action="dropped" '
             'attack="MS.SMB.Server.SMB1.Trans2.Secondary.Handling.Code.Execution" attackid=43796')
ASA_BUILT_OUT = ("<166>Sep 21 2026 10:30:00 asa01 : %ASA-6-302013: Built outbound TCP connection 44120 for "
                 "outside:198.51.100.10/443 (198.51.100.10/443) to inside:10.0.0.15/51000 (203.0.113.1/51000)")
ASA_DENY = ('<164>Sep 21 2026 10:30:01: %ASA-4-106023: Deny tcp src outside:203.0.113.77/40111 '
            'dst inside:10.0.0.20/3389 by access-group "outside_in" [0x0, 0x0]')
ASA_AAA_FAIL = ("<166>Sep 21 2026 10:30:02: %ASA-6-113015: AAA user authentication Rejected : reason = Invalid password"
                " : local database : user = admin : user IP = 203.0.113.12")
CP_DROP = ('<134>1 2026-09-21T10:40:00Z cpgw01 CheckPoint 2210 - [action:"Drop"; flags:"411908"; ifdir:"inbound"; '
           'origin:"10.9.0.1"; time:"1789987200"; version:"5"; dst:"10.9.1.5"; product:"VPN-1 & FireWall-1"; '
           'proto:"6"; s_port:"50111"; service:"22"; src:"203.0.113.61"; rule_name:"Cleanup"]')
SRX_DENY = ('<14>1 2026-09-21T10:45:00.000+05:30 srx01 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.129 '
            'source-address="10.3.3.3" source-port="55000" destination-address="198.51.100.3" destination-port="22" '
            'service-name="junos-ssh" protocol-id="6" policy-name="deny-all" source-zone-name="trust" '
            'destination-zone-name="untrust"]')
SRX_PLAIN = "RT_FLOW: RT_FLOW_SESSION_DENY: session denied 10.1.2.3/38328->203.0.113.5/443 junos-https 6(0) deny-all trust untrust"
SOPHOS = ('<30>device="SFW" date=2026-09-21 time=10:50:00 timezone="IST" device_name="XGS2100" log_id=010101600001 '
          'log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny" priority=Information '
          'fw_rule_id=5 user_name="" src_ip=10.5.5.5 src_port=51000 dst_ip=198.51.100.66 dst_port=25 protocol="TCP"')
SONICWALL = ('<134>Sep 21 10:55:00 192.0.2.1 id=firewall sn=0017C5000001 time="2026-09-21 10:55:00" fw=192.0.2.1 pri=6 '
             'c=262144 m=98 msg="Connection Opened" n=100 src=10.6.6.6:52100:X0 dst=198.51.100.99:443:X1 proto=tcp/https')
PFSENSE = ("<134>Sep 21 11:00:00 fw.example filterlog[4410]: 5,,,1000000103,igb1,match,block,in,4,0x0,,64,34211,0,DF,6,"
           "tcp,60,203.0.113.9,10.7.7.7,44321,22,0,S,2155013399,,64240,,mss;sackOK;TS;nop;wscale")
SURICATA = ('{"timestamp":"2026-09-21T11:05:00.123456+0000","flow_id":1,"event_type":"alert","src_ip":"203.0.113.30",'
            '"src_port":4444,"dest_ip":"10.8.8.8","dest_port":80,"proto":"TCP","alert":{"action":"blocked",'
            '"signature_id":2024217,"signature":"ET WEB_SERVER Possible SQL Injection","category":"Web Application Attack",'
            '"severity":1}}')
ZEEK = ('{"ts":1789988700.5,"uid":"CabC123","id.orig_h":"10.9.9.9","id.orig_p":50000,"id.resp_h":"198.51.100.53",'
        '"id.resp_p":53,"proto":"udp","service":"dns","orig_bytes":40,"resp_bytes":120,"conn_state":"SF"}')
SNORT = ("09/21-11:10:00.000001  [**] [1:2003068:6] ET SCAN Potential SSH Scan OUTBOUND [**] "
         "[Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.4.4.4:51515 -> 198.51.100.22:22")


@pytest.mark.parametrize("line,pack,class_uid,src,dst", [
    (PAN_TRAFFIC, "paloalto_panos", 4001, "10.20.4.5", "203.0.113.80"),
    (PAN_THREAT, "paloalto_panos", 2004, "203.0.113.50", "10.20.4.9"),
    (FORTI_TRAFFIC, "fortinet_fortigate", 4001, "10.1.1.20", "198.51.100.25"),
    (FORTI_IPS, "fortinet_fortigate", 2004, "203.0.113.44", "10.1.1.30"),
    (ASA_BUILT_OUT, "cisco_asa", 4001, "10.0.0.15", "198.51.100.10"),
    (ASA_DENY, "cisco_asa", 4001, "203.0.113.77", "10.0.0.20"),
    (CP_DROP, "checkpoint_log_exporter", 4001, "203.0.113.61", "10.9.1.5"),
    (SRX_DENY, "juniper_srx", 4001, "10.3.3.3", "198.51.100.3"),
    (SRX_PLAIN, "juniper_srx", 4001, "10.1.2.3", "203.0.113.5"),
    (SOPHOS, "sophos_firewall", 4001, "10.5.5.5", "198.51.100.66"),
    (SONICWALL, "sonicwall_sonicos", 4001, "10.6.6.6", "198.51.100.99"),
    (PFSENSE, "pfsense_filterlog", 4001, "203.0.113.9", "10.7.7.7"),
    (SURICATA, "suricata_eve", 2004, "203.0.113.30", "10.8.8.8"),
    (ZEEK, "zeek_json", 4001, "10.9.9.9", "198.51.100.53"),
    (SNORT, "snort_alert", 2004, "10.4.4.4", "198.51.100.22"),
])
def test_pack_detects_and_maps_endpoints(line, pack, class_uid, src, dst):
    fmt, parsed, ev = norm(line)
    assert fmt == pack
    assert ev.class_uid == class_uid
    assert ev.type_uid == ev.class_uid * 100 + ev.activity_id
    assert ev.src_endpoint.ip == src and ev.dst_endpoint.ip == dst
    assert ev.unmapped["parser_pack"] == pack
    assert ev.unmapped["vendor_fields"], "device fields must be preserved"


def test_deny_maps_to_refuse_activity():
    for line in (FORTI_TRAFFIC, ASA_DENY, CP_DROP, SRX_DENY, SOPHOS, PFSENSE):
        _, _, ev = norm(line)
        assert (ev.activity_id, ev.activity_name) == (5, "Refuse"), line[:40]


def test_panos_traffic_fields_and_device_time():
    _, parsed, ev = norm(PAN_TRAFFIC)
    assert (ev.src_endpoint.port, ev.dst_endpoint.port) == (51514, 443)
    assert ev.traffic.bytes_out == 1200 and ev.traffic.bytes_in == 8600
    assert ev.user.name == "corp\\alice"
    assert ev.time.startswith("2026-09-21T10:15:01")
    assert ev.activity_name == "Close"


def test_panos_threat_splits_name_and_id():
    _, parsed, ev = norm(PAN_THREAT)
    assert ev.finding.title == "Apache Struts2 Remote Code Execution Vulnerability"
    assert parsed["rule_id"] == "33240"
    assert ev.severity == "Critical"


def test_fortigate_vpn_failure_is_authentication_failure():
    _, _, ev = norm(FORTI_VPN_FAIL)
    assert ev.class_uid == 3002 and ev.status == "failure"
    assert ev.user.name == "bob" and ev.src_endpoint.ip == "203.0.113.99"


def test_fortigate_uses_eventtime_not_local_clock():
    _, _, ev = norm(FORTI_TRAFFIC)
    assert ev.time.startswith("2026-09-21T")


def test_asa_outbound_direction_puts_inside_host_as_source():
    _, parsed, _ = norm(ASA_BUILT_OUT)
    assert parsed["direction"] == "outbound" and parsed["src_port"] == 51000


def test_asa_aaa_rejection_is_failed_logon():
    _, _, ev = norm(ASA_AAA_FAIL)
    assert ev.class_uid == 3002 and ev.status == "failure" and ev.user.name == "admin"


def test_suricata_numeric_severity_is_inverted_correctly():
    _, _, ev = norm(SURICATA)
    assert ev.severity == "High"  # Suricata severity 1 is the most severe
    assert ev.finding.title == "ET WEB_SERVER Possible SQL Injection"


def test_unknown_device_text_is_base_event_not_network_activity():
    _, _, ev = norm("<13>Sep 21 11:15:00 router7 kernel: link state changed on port 3")
    assert ev.class_uid == 0 and ev.type_uid == 99


def test_envelope_keeps_structured_data_and_message():
    env = split_envelope(SRX_DENY)
    assert env.standard == "rfc5424" and env.hostname == "srx01" and env.msgid == "RT_FLOW_SESSION_DENY"
    assert env.sd["junos@2636.1.1.1.2.129"]["policy-name"] == "deny-all"


def test_envelope_handles_asa_without_hostname():
    env = split_envelope(ASA_DENY)
    assert env.hostname is None and env.message.startswith("%ASA-4-106023")


@pytest.mark.parametrize("status, outcome", [("success", "success"), ("failure", "failure"), ("failed", "failure")])
def test_fortigate_login_outcome_follows_the_status_field(status, outcome):
    # the description says only "login"; status= is the device's verdict and must not be ignored
    line = ('date=2026-09-20 time=14:00:00 devname="FGT-VPN" type="event" subtype="vpn" action="login" '
            f'status="{status}" user="bob" srcip=198.51.100.22 dstip=10.0.1.15')
    fmt, parsed, _ = norm(line)
    assert fmt == "fortinet_fortigate" and parsed["auth_status"] == outcome and parsed["action"] == outcome

