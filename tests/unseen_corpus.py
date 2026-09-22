"""
Log formats TRACELOG has no vendor pack for, each with the true values a human analyst
reads from the line. Used to score the fallback parser: a field it fills with a value
that differs from the truth is WRONG (must never happen); a field it leaves empty is
MISSED (acceptable, a learned parser fills it later).

Truth keys: src_ip, src_port, dst_ip, dst_port, protocol, action ("allowed" or
"denied"), time ("YYYY-MM-DDTHH:MM:SS", or "MM-DDTHH:MM:SS" when the line has no year),
severity (OCSF label), class_uid, user. A key left out is not scored.
"""
from tests.test_vendor_packs import PAN_TRAFFIC

# PAN-OS after a firmware change inserted a new column after time_generated: every later
# field shifts by one. The Palo Alto pack still recognises the line; its values are now wrong.
_parts = PAN_TRAFFIC.split(",")
PAN_TRAFFIC_DRIFTED = ",".join(_parts[:7] + ["NEWCOL"] + _parts[7:])

CORPUS = [
    {"name": "Huawei USG6000",
     "line": "<188>Sep 21 2026 10:00:00 USG6000 %%01POLICY/6/POLICYPERMIT(l):vsys=public, protocol=6, "
             "source-ip=10.1.1.1, source-port=5000, destination-ip=8.8.8.8, destination-port=443, "
             "time=2026/9/21 10:00:00, source-zone=trust, destination-zone=untrust, rule-name=allow.",
     "truth": {"src_ip": "10.1.1.1", "src_port": 5000, "dst_ip": "8.8.8.8", "dst_port": 443, "protocol": "TCP",
               "action": "allowed", "time": "2026-09-21T10:00:00", "severity": "Medium", "class_uid": 4001}},
    {"name": "Cisco Meraki MX (flows)",
     "line": "<134>1 1789984800.123456789 MX84 flows src=10.0.0.5 dst=8.8.8.8 mac=00:11:22:33:44:55 "
             "protocol=udp sport=53042 dport=53 pattern: allow all",
     "truth": {"src_ip": "10.0.0.5", "src_port": 53042, "dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP",
               "action": "allowed", "time": "2026-09-21T10:00:00", "severity": "Informational", "class_uid": 4001}},
    {"name": "MikroTik RouterOS",
     "line": "<134>Sep 21 10:00:00 MikroTik forward: in:ether1 out:bridge, src-mac 00:11:22:33:44:55, "
             "proto TCP (SYN), 203.0.113.5:51234->192.168.88.10:22, len 60",
     "truth": {"src_ip": "203.0.113.5", "src_port": 51234, "dst_ip": "192.168.88.10", "dst_port": 22,
               "protocol": "TCP", "time": "09-21T10:00:00", "severity": "Informational", "class_uid": 4001}},
    {"name": "Ubiquiti USG (iptables)",
     "line": "<4>Sep 21 10:00:00 USG kernel: [WAN_LOCAL-default-D]IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff "
             "SRC=203.0.113.7 DST=198.51.100.2 LEN=40 TOS=0x00 PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=41234 "
             "DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0",
     "truth": {"src_ip": "203.0.113.7", "src_port": 41234, "dst_ip": "198.51.100.2", "dst_port": 23,
               "protocol": "TCP", "action": "denied", "time": "09-21T10:00:00", "severity": "Medium",
               "class_uid": 4001}},
    {"name": "F5 BIG-IP ASM",
     "line": '<134>Sep 21 10:00:00 bigip1 ASM:unit_hostname="bigip1",management_ip_address="192.168.1.245",'
             'ip_client="203.0.113.9",src_port="51514",dest_ip="10.1.1.20",dest_port="443",method="POST",'
             'uri="/login",violation_rating="4",severity="Critical",request_status="blocked",'
             'attack_type="SQL-Injection"',
     "truth": {"src_ip": "203.0.113.9", "src_port": 51514, "dst_ip": "10.1.1.20", "dst_port": 443,
               "action": "denied", "time": "09-21T10:00:00", "severity": "Critical", "class_uid": 2004}},
    {"name": "Barracuda CloudGen",
     "line": "<134>Sep 21 10:00:00 bcfw Block: type=FWD|proto=TCP|srcIF=p1|srcIP=10.0.0.5|srcPort=51000|"
             "dstIP=8.8.8.8|dstPort=443|dstIF=p2|rule=BLOCKALL|info=Block|srcNAT=0.0.0.0",
     "truth": {"src_ip": "10.0.0.5", "src_port": 51000, "dst_ip": "8.8.8.8", "dst_port": 443, "protocol": "TCP",
               "action": "denied", "time": "09-21T10:00:00", "severity": "Informational", "class_uid": 4001}},
    {"name": "WatchGuard Firebox",
     "line": '<142>Sep 21 10:00:00 WatchGuard-XTM FVE123 firewall: msg_id="3000-0148" Deny 1-Trusted 0-External '
             '60 tcp 20 64 10.0.1.5 203.0.113.9 51514 443 offset 10 S 3141592 win 8192 (Unhandled Internal Packet-00)',
     "truth": {"src_ip": "10.0.1.5", "src_port": 51514, "dst_ip": "203.0.113.9", "dst_port": 443, "protocol": "TCP",
               "action": "denied", "time": "09-21T10:00:00", "severity": "Informational", "class_uid": 4001}},
    {"name": "AWS VPC flow log",
     "line": "2 123456789012 eni-0a1b2c3d 203.0.113.12 10.0.1.5 49761 22 6 20 4249 1789984800 1789984860 REJECT OK",
     "truth": {"src_ip": "203.0.113.12", "src_port": 49761, "dst_ip": "10.0.1.5", "dst_port": 22, "protocol": "TCP",
               "action": "denied", "time": "2026-09-21T10:00:00", "class_uid": 4001}},
    {"name": "Squid proxy",
     "line": "1789984800.123    150 10.0.0.5 TCP_DENIED/403 3712 CONNECT evil.example:443 - HIER_NONE/- text/html",
     "truth": {"src_ip": "10.0.0.5", "dst_port": 443, "action": "denied", "time": "2026-09-21T10:00:00"}},
    {"name": "Sophos UTM (packet filter)",
     "line": '<30>2026:09:21-10:00:00 utm ulogd[4242]: id="2001" severity="info" sys="SecureNet" sub="packetfilter" '
             'name="Packet dropped" action="drop" fwrule="60001" initf="eth1" srcmac="00:1a:8c:00:00:01" '
             'srcip="203.0.113.44" dstip="10.0.0.9" proto="6" length="60" tos="0x00" prec="0x00" ttl="52" '
             'srcport="44321" dstport="22" tcpflags="SYN"',
     "truth": {"src_ip": "203.0.113.44", "src_port": 44321, "dst_ip": "10.0.0.9", "dst_port": 22, "protocol": "TCP",
               "action": "denied", "time": "2026-09-21T10:00:00", "severity": "Informational", "class_uid": 4001}},
    {"name": "Zscaler NSS (JSON)",
     "line": '{"sourcetype":"zscalernss-web","event":{"datetime":"Mon Sep 21 10:00:00 2026","clientip":"10.0.0.7",'
             '"serverip":"93.184.216.34","action":"Blocked","urlcategory":"Malware","threatname":"EICAR_Test_File",'
             '"login":"ravi@corp.example","protocol":"HTTPS"}}',
     "truth": {"src_ip": "10.0.0.7", "dst_ip": "93.184.216.34", "action": "denied", "time": "2026-09-21T10:00:00",
               "class_uid": 2004, "user": "ravi@corp.example"}},
    {"name": "Juniper ScreenOS",
     "line": '<134>ns5gt: NetScreen device_id=ns5gt  [Root]system-notification-00257(traffic): '
             'start_time="2026-09-21 10:00:00" duration=0 policy_id=2 service=http proto=6 src zone=Trust '
             'dst zone=Untrust action=Deny sent=0 rcvd=0 src=10.0.0.3 dst=93.184.216.34 src_port=51000 '
             'dst_port=80 session_id=0',
     "truth": {"src_ip": "10.0.0.3", "src_port": 51000, "dst_ip": "93.184.216.34", "dst_port": 80, "protocol": "TCP",
               "action": "denied", "time": "2026-09-21T10:00:00", "severity": "Informational", "class_uid": 4001}},
    {"name": "PAN-OS after a firmware change (column inserted)",
     "line": PAN_TRAFFIC_DRIFTED,
     "truth": {"src_ip": "10.20.4.5", "dst_ip": "203.0.113.80", "src_port": 51514, "dst_port": 443,
               "protocol": "TCP", "action": "allowed"}},
]

SCORED = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", "action", "time", "severity", "class_uid", "user")


def observed(ev):
    """Pull the scored fields out of a normalised event (OCSFEvent.model_dump())."""
    src, dst = ev.get("src_endpoint") or {}, ev.get("dst_endpoint") or {}
    disp = str(ev.get("disposition") or ev.get("action") or "").lower()
    action = "allowed" if disp.startswith("allow") else "denied" if disp and disp[:4] in (
        "deny", "deni", "bloc", "drop", "reje", "refu") else None
    un = ev.get("unmapped") or {}
    time = None if un.get("time_source") == "received" else ev.get("time")
    return {"src_ip": src.get("ip"), "src_port": src.get("port"), "dst_ip": dst.get("ip"), "dst_port": dst.get("port"),
            "protocol": ((ev.get("connection_info") or {}).get("protocol_name") or None),
            "action": action, "time": time, "severity": ev.get("severity"), "class_uid": ev.get("class_uid"),
            "user": (ev.get("user") or {}).get("name")}


def score(ev, truth):
    """Returns (wrong, missed, correct) lists of field names."""
    got = observed(ev)
    wrong, missed, correct = [], [], []
    for k, want in truth.items():
        have = got.get(k)
        if k == "protocol" and have is not None:
            have = str(have).upper()
        if k == "time" and have is not None:
            have = str(have)[:19] if len(want) == 19 else str(have)[5:19]
        if k == "class_uid" and have == 0:
            have = None  # a Base Event claims no class: missed, not wrong
        if have is None or have == "":
            missed.append(k)
        elif have == want:
            correct.append(k)
        else:
            wrong.append(f"{k}={have!r} (truth {want!r})")
    return wrong, missed, correct
