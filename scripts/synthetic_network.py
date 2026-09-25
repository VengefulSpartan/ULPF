"""
A synthetic day of perimeter logs with attacks injected at known times, for evaluating the baseline
detector (scripts/evaluate_baseline.py) and for its tests.

Everything is written as FortiGate syslog lines (traffic, SSL-VPN login, IPS), so the evaluation runs
the real pipeline end to end: the lines are archived, parsed by the FortiGate pack, normalised to OCSF
and hash-chained, and the features are computed from what was stored, not from the generator's own
numbers.

The network, all addresses from documentation and private ranges:

  internal hosts      10.10.1.0/24 - 10.10.3.0/24, each with its own rate, a set of usual external
                      destinations (and a few new ones), mostly 443/80/53, a daily rhythm peaking in
                      Indian office hours, and about 1% of its connections denied
  backup server       10.10.3.5 uploads about 300 MB once, at 20:00 UTC (01:30 IST): benign, and
                      exactly the kind of thing a baseline with 24 h of history will flag, so it is in
                      the data
  internet noise      a steady trickle of scanners, mostly a new address each time, hitting the DMZ on
                      common ports and denied; a few trip an IPS signature
  VPN users           25 users logging in from their usual addresses during office hours; about 8% of
                      attempts are mistyped passwords

Attacks, all after the first 12 hours so the detector has history (entity: who a flag should name):

  fast port sweep     203.0.113.66 -> DMZ, 80 ports in 90 s                       src_ip
  VPN brute force     192.0.2.77, 40 failed logins as "admin", then a success      src_ip, user admin
  password spray      192.0.2.88, one failed login for each of 20 users            src_ip
  exfiltration        an ordinary host sends ~800 MB to a new address in 10 min   src_ip
  lateral SMB scan    an ordinary host -> 60 internal hosts on 445 in 3 min       src_ip
  distributed scan    300 addresses, one probe each, in 4 min                     device FGT-HQ
  slow port scan      203.0.113.99, one port every 2 min for 2 h                  src_ip   (expected miss)
  slow exfiltration   an ordinary host, ~20 MB extra every 5 min for 2 h          src_ip   (expected miss)

The two "expected miss" attacks are there on purpose: each window of them stays under the smallest
increase the detector flags (backend/services/ml/baseline.py, MIN_EXCESS), so a per-window baseline
cannot see them. They show what the detector does not do.
"""
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

DEVICE = "FGT-HQ"
START = datetime(2026, 9, 21, 0, 0, 0, tzinfo=timezone.utc)
DMZ = [f"10.10.9.{i}" for i in (10, 20, 30)]
DNS = "10.10.0.53"
USERS = [f"user{i:02d}" for i in range(1, 26)]
BACKUP_HOST = "10.10.3.5"


@dataclass
class Attack:
    name: str
    start_ms: int
    end_ms: int
    entities: List[Tuple[str, str]]          # (entity_type, entity) a flag may name
    expected_miss: bool = False
    note: str = ""


@dataclass
class Scenario:
    lines: List[Tuple[int, str]] = field(default_factory=list)     # (epoch ms, syslog line)
    attacks: List[Attack] = field(default_factory=list)
    benign_notes: List[Tuple[str, str, int, int, str]] = field(default_factory=list)  # type, entity, start, end, why
    start_ms: int = 0
    end_ms: int = 0


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _fgt(ts_ms: int, body: str) -> str:
    dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    return (f'<189>date={dt:%Y-%m-%d} time={dt:%H:%M:%S} devname="{DEVICE}" devid="FG100FTK19000001" '
            f'eventtime={ts_ms * 1_000_000} tz="+0000" {body}')


def traffic(ts: int, src: str, dst: str, dport: int, rng: random.Random, action: str = "close",
            sent: int = 0, rcvd: int = 0, proto: int = 6) -> str:
    return _fgt(ts, f'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
                    f'srcip={src} srcport={rng.randint(32768, 60999)} srcintf="port2" dstip={dst} dstport={dport} '
                    f'dstintf="wan1" proto={proto} action="{action}" policyid=12 sentbyte={sent} rcvdbyte={rcvd}')


def vpn_login(ts: int, user: str, remip: str, ok: bool) -> str:
    if ok:
        return _fgt(ts, f'logid="0101039947" type="event" subtype="vpn" level="information" vd="root" '
                        f'logdesc="SSL VPN tunnel up" action="tunnel-up" tunneltype="ssl-tunnel" status="success" '
                        f'remip={remip} user="{user}" msg="SSL tunnel established"')
    return _fgt(ts, f'logid="0101039426" type="event" subtype="vpn" level="alert" vd="root" '
                    f'logdesc="SSL VPN login fail" action="ssl-login-fail" tunneltype="ssl-web" status="failure" '
                    f'remip={remip} user="{user}" reason="sslvpn_login_permission_denied" '
                    f'msg="SSL user failed to logged in"')


def ips(ts: int, src: str, dst: str, dport: int, rng: random.Random) -> str:
    sig = rng.choice(["SSH.Brute.Force", "MS.SMB.Server.SMB1.Trans2.Secondary.Handling.Code.Execution",
                      "Apache.Log4j.Error.Log.Remote.Code.Execution", "Telnet.Login.Brute.Force"])
    return _fgt(ts, f'logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" '
                    f'severity="high" srcip={src} dstip={dst} srcport={rng.randint(1024, 65000)} dstport={dport} '
                    f'proto=6 action="dropped" attack="{sig}" attackid={rng.randint(10000, 60000)}')


def _office_factor(hour: float) -> float:
    """Activity relative to the peak: office hours in India (03:30-12:30 UTC) are busy, nights quiet."""
    if 3.5 <= hour <= 12.5:
        return 0.3 + 0.7 * math.sin(math.pi * (hour - 3.5) / 9.0)
    return 0.12


def _poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 50:
        return max(0, int(round(rng.gauss(lam, math.sqrt(lam)))))
    k, p, limit = 0, 1.0, math.exp(-lam)
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def generate(seed: int = 1, hours: int = 24, hosts: int = 30, attacks: bool = True) -> Scenario:
    rng = random.Random(seed)
    start = _ms(START)
    end = start + hours * 3600 * 1000
    window = 5 * 60 * 1000
    sc = Scenario(start_ms=start, end_ms=end)
    out = sc.lines

    internal = [f"10.10.{1 + i // 12}.{20 + i % 12}" for i in range(hosts)]
    external_pool = [f"198.51.100.{i}" for i in range(1, 255)] + [f"203.0.113.{i}" for i in range(100, 200)]
    profiles = {}
    for host in internal:
        profiles[host] = {
            "rate": min(40.0, rng.lognormvariate(math.log(8), 0.6)),   # connections per 5 min at the peak
            "usual": rng.sample(external_pool, 15),
            "sent_mu": math.log(rng.uniform(1500, 6000)),
        }
    user_home = {u: f"100.64.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for u in USERS}
    ports = [443] * 70 + [80] * 15 + [53] * 10 + [22, 123, 993, 587, 8443]

    # ordinary traffic, window by window
    for w in range(start, end, window):
        hour = ((w - start) / 3_600_000) % 24
        busy = _office_factor(hour)
        for host, p in profiles.items():
            for _ in range(_poisson(rng, p["rate"] * busy)):
                ts = w + rng.randrange(window)
                port = rng.choice(ports)
                if port == 53:
                    dst = DNS
                elif rng.random() < 0.05:
                    dst = rng.choice(external_pool)
                else:
                    dst = rng.choice(p["usual"])
                if rng.random() < 0.01:
                    out.append((ts, traffic(ts, host, dst, port, rng, action="deny")))
                else:
                    sent = int(rng.lognormvariate(p["sent_mu"], 1.2))
                    rcvd = int(rng.lognormvariate(math.log(20000), 1.8))
                    out.append((ts, traffic(ts, host, dst, port, rng, sent=sent, rcvd=rcvd,
                                            proto=17 if port in (53, 123) else 6)))
        # internet background: scanners, mostly new addresses, denied at the edge
        for _ in range(_poisson(rng, 8)):
            ts = w + rng.randrange(window)
            scanner = f"{rng.choice([45, 80, 91, 141, 185, 193])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}." \
                      f"{rng.randint(1, 254)}"
            target = rng.choice(DMZ)
            for _ in range(rng.randint(1, 3)):
                t2 = ts + rng.randrange(5000)
                out.append((t2, traffic(t2, scanner, target, rng.choice([22, 23, 445, 3389, 80, 443, 8080]), rng,
                                        action="deny")))
            if rng.random() < 0.03:
                out.append((ts, ips(ts, scanner, target, 445, rng)))
        # VPN: office-hours logins, sometimes mistyped
        for user in USERS:
            if rng.random() < 0.05 * busy:
                ts = w + rng.randrange(window)
                while rng.random() < 0.08:
                    out.append((ts, vpn_login(ts, user, user_home[user], ok=False)))
                    ts += rng.randint(3000, 20000)
                out.append((ts, vpn_login(ts, user, user_home[user], ok=True)))

    # the benign surprise: the nightly backup, once in this day
    b = start + 20 * 3600 * 1000
    for i in range(12):
        ts = b + i * 20000
        out.append((ts, traffic(ts, BACKUP_HOST, "10.10.8.8", 22, rng, sent=25_000_000 + rng.randint(0, 10**6),
                                rcvd=40_000)))
    for w in range(start, end, window):      # the backup server's ordinary chatter
        for _ in range(_poisson(rng, 3)):
            ts = w + rng.randrange(window)
            out.append((ts, traffic(ts, BACKUP_HOST, DNS, 53, rng, sent=80, rcvd=200, proto=17)))
    sc.benign_notes.append(("src_ip", BACKUP_HOST, b, b + 12 * 20000, "the nightly backup, ~300 MB over SSH"))

    if attacks:
        _inject(sc, rng, start, internal, external_pool)
    out.sort(key=lambda x: x[0])
    return sc


def _inject(sc: Scenario, rng: random.Random, start: int, internal: List[str], external_pool: List[str]) -> None:
    out, H, M = sc.lines, 3600 * 1000, 60 * 1000

    def add(name, t0, t1, entities, miss=False, note=""):
        sc.attacks.append(Attack(name, t0, t1, entities, miss, note))

    # fast port sweep: 80 ports in 90 s
    t0 = start + 13 * H + 7 * M
    ports = rng.sample(range(1, 10000), 80)
    for i, port in enumerate(ports):
        ts = t0 + int(i * 90000 / 80)
        out.append((ts, traffic(ts, "203.0.113.66", DMZ[1], port, rng, action="deny")))
    add("fast port sweep", t0, t0 + 90000, [("src_ip", "203.0.113.66"), ("device", DEVICE)],
        note="80 ports in 90 s from an address never seen before")

    # VPN brute force against admin, then a success
    t0 = start + 14 * H + 21 * M
    for i in range(40):
        ts = t0 + i * 6000
        out.append((ts, vpn_login(ts, "admin", "192.0.2.77", ok=False)))
    out.append((t0 + 245000, vpn_login(t0 + 245000, "admin", "192.0.2.77", ok=True)))
    add("VPN brute force", t0, t0 + 245000, [("src_ip", "192.0.2.77"), ("user", "admin")],
        note="40 failed logins as admin in 4 min, then a success")

    # password spray: one attempt per user
    t0 = start + 15 * H + 2 * M
    for i, user in enumerate(USERS[:20]):
        ts = t0 + i * 12000
        out.append((ts, vpn_login(ts, user, "192.0.2.88", ok=False)))
    add("password spray", t0, t0 + 20 * 12000, [("src_ip", "192.0.2.88")],
        note="one failed login for each of 20 users")

    # exfiltration burst from an ordinary host to a new address
    exfil, lateral, slow = internal[len(internal) // 2], internal[1], internal[-1]
    t0 = start + 16 * H + 33 * M
    for i in range(20):
        ts = t0 + i * 30000
        out.append((ts, traffic(ts, exfil, "198.18.0.50", 443, rng, sent=40_000_000, rcvd=9_000)))
    add("exfiltration burst", t0, t0 + 20 * 30000, [("src_ip", exfil)],
        note="~800 MB to a new address in 10 min")

    # lateral SMB scan
    t0 = start + 17 * H + 11 * M
    for i in range(60):
        ts = t0 + i * 3000
        out.append((ts, traffic(ts, lateral, f"10.10.{4 + i // 30}.{10 + i % 30}", 445, rng,
                                action="close" if i % 3 else "deny", sent=300, rcvd=0)))
    add("lateral SMB scan", t0, t0 + 180000, [("src_ip", lateral)], note="60 internal hosts on 445 in 3 min")

    # distributed scan: 300 addresses, one probe each
    t0 = start + 18 * H + 41 * M
    for i in range(300):
        ts = t0 + int(i * 240000 / 300)
        src = f"192.0.2.{100 + i}" if i < 150 else f"198.51.100.{i - 50}"
        out.append((ts, traffic(ts, src, DMZ[0], 3389, rng, action="deny")))
    add("distributed scan", t0, t0 + 240000, [("device", DEVICE)], note="300 addresses, one probe each, in 4 min")

    # slow port scan: one port every 2 minutes for 2 hours
    t0 = start + 19 * H + 3 * M
    for i in range(60):
        ts = t0 + i * 120000
        out.append((ts, traffic(ts, "203.0.113.99", DMZ[2], 1000 + i * 7, rng, action="deny")))
    add("slow port scan", t0, t0 + 60 * 120000, [("src_ip", "203.0.113.99")], miss=True,
        note="2-3 ports per 5 min, under the 15-port minimum")

    # slow exfiltration: ~20 MB extra per window for 2 hours
    t0 = start + 21 * H + 1 * M
    for i in range(24):
        ts = t0 + i * 300000 + rng.randrange(60000)
        out.append((ts, traffic(ts, slow, "198.18.0.77", 443, rng, sent=20_000_000, rcvd=5_000)))
    add("slow exfiltration", t0, t0 + 24 * 300000, [("src_ip", slow)], miss=True,
        note="~20 MB per 5 min, under the 50 MB minimum")
