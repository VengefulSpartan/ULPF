"""
Many lines of formats TRACELOG has no pack for, each with its true values, for learning and
testing parsers. Values vary the way they do on a real device (addresses, ports, actions,
times, users); the structure of each format stays fixed.
"""
import random
from datetime import datetime, timedelta, timezone

BASE = datetime(2026, 9, 21, 10, 0, 0, tzinfo=timezone.utc)
SERVICES = [443, 80, 22, 53, 3389, 25, 8443, 445]


def _rng(seed):
    return random.Random(seed)


def _internal(r):
    return f"10.{r.randint(0, 3)}.{r.randint(0, 255)}.{r.randint(2, 254)}"


def _external(r):
    return f"{r.choice([203, 198, 93, 185])}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"


def watchguard(n=120, seed=1):
    """WatchGuard Firebox traffic: addresses and ports by position only (no src/dst markers)."""
    r, out = _rng(seed), []
    for i in range(n):
        t = BASE + timedelta(seconds=37 * i)
        allow = r.random() < 0.55
        proto = r.choice(["tcp", "tcp", "udp"])
        src, dst = _internal(r), _external(r)
        sport, dport = r.randint(1025, 65000), r.choice(SERVICES)
        trailer = "(Allow-Trusted-00)" if allow else "(Unhandled Internal Packet-00)"
        line = (f'<142>{t.strftime("%b %d %H:%M:%S")} WatchGuard-XTM FVE123 firewall: msg_id="3000-0148" '
                f'{"Allow" if allow else "Deny"} 1-Trusted 0-External {r.randint(40, 1500)} {proto} 20 '
                f'{r.randint(32, 128)} {src} {dst} {sport} {dport} offset 10 S {r.randint(10**6, 10**9)} '
                f'win {r.choice([8192, 64240, 29200])} {trailer}')
        out.append({"line": line, "truth": {
            "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport, "protocol": proto.upper(),
            "action": "allowed" if allow else "denied", "time": t.strftime("%m-%dT%H:%M:%S"),
            "severity": "Informational", "class_uid": 4001}})
    return out


def vpc_flow(n=120, seed=2):
    """AWS VPC flow log v2: space-separated, no syslog header, epoch start/end times."""
    r, out = _rng(seed), []
    for i in range(n):
        t = BASE + timedelta(seconds=11 * i)
        inbound = r.random() < 0.6
        src, dst = (_external(r), _internal(r)) if inbound else (_internal(r), _external(r))
        sport, dport = r.randint(1025, 65000), r.choice(SERVICES)
        proto = r.choice([6, 6, 6, 17])
        accept = r.random() < 0.5
        start = int(t.timestamp())
        line = (f"2 123456789012 eni-0a1b2c3d {src} {dst} {sport} {dport} {proto} {r.randint(1, 90)} "
                f"{r.randint(40, 90000)} {start} {start + 60} {'ACCEPT' if accept else 'REJECT'} OK")
        out.append({"line": line, "truth": {
            "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
            "protocol": "TCP" if proto == 6 else "UDP", "action": "allowed" if accept else "denied",
            "time": t.strftime("%Y-%m-%dT%H:%M:%S"), "class_uid": 4001}})
    return out


def ssh_auth(n=80, seed=3):
    """OpenSSH messages: one template, the user name varies (merged into one format)."""
    r, out = _rng(seed), []
    users = ["alice", "bob", "carol", "deploy", "backup", "ravi", "meena", "svc_ci"]
    for i in range(n):
        t = BASE + timedelta(seconds=53 * i)
        user, src, port = r.choice(users), _external(r), r.randint(1025, 65000)
        line = (f"<38>{t.strftime('%b %d %H:%M:%S')} bastion sshd[{r.randint(1000, 9999)}]: "
                f"Accepted password for {user} from {src} port {port} ssh2")
        out.append({"line": line, "truth": {"src_ip": src, "src_port": port, "user": user,
                                            "time": t.strftime("%m-%dT%H:%M:%S"), "class_uid": 3002}})
    return out


def lines(samples):
    return [s["line"] for s in samples]
