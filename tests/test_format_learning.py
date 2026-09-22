"""
New log formats end to end: detected as formats, a parser learned from many lines and
tested on held-out ones, reviewed and approved by a person, applied to new lines without a
restart, and past lines re-parsed as chained revisions.
"""
import json

import pytest

from backend.services.ingestion.stream import InboundRecord, StreamIngestor
from backend.services.integrity.ledger import IntegrityLedger
from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
from backend.services.parser_generation import learned, workflow
from backend.services.parser_generation.reparse import reparse_history
from backend.services.parsing.dispatch import parse_log
from backend.services.parsing.formats import list_formats, registry
from tests.format_samples import lines, ssh_auth, vpc_flow, watchguard
from tests.unseen_corpus import PAN_TRAFFIC_DRIFTED, score


@pytest.fixture
def db(isolated_db):
    registry.forget_cache()
    learned.invalidate()
    yield isolated_db
    registry.forget_cache()
    learned.invalidate()


def ingest(raw_lines, peer="192.0.2.77"):
    out = []
    for i in range(0, len(raw_lines), 50):
        out += StreamIngestor().ingest([InboundRecord(raw=l.encode(), transport="syslog-udp", input_name="udp",
                                                      peer_ip=peer) for l in raw_lines[i:i + 50]])
    return out


def formats(db):
    with db.get_connection() as conn:
        return list_formats(conn)


def normalized(line):
    _, parsed = parse_log(line)
    return parsed, OCSFNormalizer.normalize(parsed, line, "r", "h", vendor=parsed.get("vendor") or "Generic",
                                            product=parsed.get("product") or "Device").model_dump()


def learn_and_approve(db, fmt_id, reviewer="asha"):
    cand = workflow.learn_format(fmt_id, vendor="WatchGuard", product="Firebox")
    return workflow.approve(cand["id"], reviewer, [s["id"] for s in cand["needs_review"]])


def test_unknown_lines_are_grouped_into_formats(db):
    ingest(lines(watchguard(60)) + lines(vpc_flow(60)) + lines(ssh_auth(40)))
    fmts = formats(db)
    assert sum(f["count"] for f in fmts) == 160
    assert all(f["status"] == "new" and f["samples"] <= 200 and f["first_seen"] and f["sources"] for f in fmts)
    ssh = [f for f in fmts if f["app"] == "sshd"]
    # eight different users, one format: the user name became a wildcard, 'from' and 'port' did not
    assert len(ssh) == 1 and ssh[0]["count"] == 40 and "for <*> from <IP> port <N>" in ssh[0]["template"]
    vpc = [f for f in fmts if f["template"].startswith("<N> <N> eni-")]
    assert len(vpc) == 1 and vpc[0]["count"] == 60


def test_a_drifted_pack_format_is_flagged(db):
    ingest([PAN_TRAFFIC_DRIFTED])
    (fmt,) = formats(db)
    assert fmt["drift_from"] == "paloalto_panos" and fmt["kind"] == "delimited"


def test_learn_review_approve_apply_and_reparse(db):
    history = watchguard(120)
    stored = ingest(lines(history))
    assert all(s.normalized["src_endpoint"]["ip"] is None for s in stored)  # generic parser: direction unknown
    fmts = sorted(formats(db), key=lambda f: -f["count"])
    assert len(fmts) == 2  # Allow and Deny lines end differently: two formats

    cand = workflow.learn_format(fmts[0]["format_id"], vendor="WatchGuard", product="Firebox")
    roles = {s["role"]: s for s in cand["spec"]["slots"] if s["role"]}
    assert {"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action", "time", "severity"} <= set(roles)
    assert {s["role"] for s in cand["needs_review"]} == {"src_ip", "dst_ip", "src_port", "dst_port"}
    assert "position only" in roles["src_ip"]["why"]
    val = cand["validation"]
    assert val["held_out"] and val["recognised"] == val["total_samples"] == val["passed_samples"]
    assert not val["disagreements"] and val["gained"]["src_ip"] == val["total_samples"]

    # the gate: positional fields must be confirmed by a named person
    with pytest.raises(workflow.WorkflowError) as exc:
        workflow.approve(cand["id"], "asha")
    assert "must be confirmed" in str(exc.value) and exc.value.detail["needs_review"]
    with pytest.raises(workflow.WorkflowError):
        workflow.approve(cand["id"], "  ", [s["id"] for s in cand["needs_review"]])
    done = workflow.approve(cand["id"], "asha", [s["id"] for s in cand["needs_review"]])
    assert done["status"] == "approved" and done["approved_by"] == "asha"
    assert set(done["formats"]) == {f["format_id"] for f in fmts}  # the other ending is claimed too
    assert done["reparse_candidates"] == 120

    # live: new lines of both endings are parsed by the approved parser, with every field right
    for case in watchguard(40, seed=99):
        parsed, ev = normalized(case["line"])
        assert parsed["tracelog_parse"]["parser_id"] == cand["id"] and parsed["tracelog_parse"]["verified"]
        wrong, missed, _ = score(ev, case["truth"])
        assert wrong == [] and missed == [], (case["line"], wrong, missed)

    # history: re-parsed as chained revisions, nothing overwritten
    stats = reparse_history(cand["id"])
    assert stats["examined"] == stats["revised"] == 120 and stats["failed"] == 0
    assert reparse_history(cand["id"])["revised"] == 0  # idempotent
    with db.get_connection() as conn:
        rows = conn.execute("SELECT n.id, n.normalized_json, n.unmapped_json, n.superseded_by, r.raw_text "
                            "FROM normalized_events n JOIN raw_logs r ON r.id = n.raw_id ORDER BY n.sequence_num"
                            ).fetchall()
    originals, revisions = rows[:120], rows[120:]
    assert len(revisions) == 120 and all(r["superseded_by"] for r in originals)
    truth = {c["line"]: c["truth"] for c in history}
    by_id = {r["id"]: r for r in originals}
    for r in revisions:
        rev = json.loads(r["unmapped_json"])["tracelog_revision"]
        assert by_id[rev["supersedes"]]["superseded_by"] == r["id"] and rev["approved_by"] == "asha"
        wrong, missed, _ = score(json.loads(r["normalized_json"]), truth[r["raw_text"]])
        assert wrong == [] and missed == []
    assert IntegrityLedger.verify_chain().is_valid

    from backend.services.integrity.reconcile import _pipeline
    pipe = _pipeline()
    assert pipe["consistent"] and pipe["raw_archived"] == pipe["original_events"] == 120
    assert pipe["revisions"] == 120 and pipe["hash_chained"] == pipe["normalized"] == 240

    from backend.api.events import list_events
    listed = list_events(limit=500, offset=0, include_superseded=False)
    assert listed["total"] == 120 and all(e["src_ip"] for e in listed["events"])
    assert list_events(limit=500, offset=0, include_superseded=True)["total"] == 240


def test_values_that_say_what_they_are_need_no_review(db):
    """Keyed format: key names and valid values are enough evidence; nothing waits for review."""
    base = ('<30>2026:09:21-10:00:{s:02d} utm ulogd[4242]: id="2001" severity="info" sys="SecureNet" '
            'sub="packetfilter" name="Packet dropped" action="drop" fwrule="60001" initf="eth1" '
            'srcip="203.0.113.{a}" dstip="10.0.0.{b}" proto="6" length="60" srcport="{p}" dstport="22" tcpflags="SYN"')
    ingest([base.format(s=i % 60, a=i + 1, b=200 - i, p=40000 + i) for i in range(40)])
    (fmt,) = formats(db)
    cand = workflow.learn_format(fmt["format_id"])
    roles = {s["role"]: s["id"] for s in cand["spec"]["slots"] if s["role"]}
    assert roles["src_ip"] == "k:srcip" and roles["dst_port"] == "k:dstport" and roles["action"] == "k:action"
    assert cand["needs_review"] == []
    assert workflow.approve(cand["id"], "asha")["status"] == "approved"


def test_learned_parser_with_impossible_values_falls_back(db):
    ingest(lines(vpc_flow(80)))
    (fmt,) = formats(db)
    learn_and_approve(db, fmt["format_id"])
    good = vpc_flow(5, seed=42)[0]
    parsed, ev = normalized(good["line"])
    assert parsed["tracelog_parse"]["verified"] and score(ev, good["truth"])[0] == []
    # same shape, impossible values (address 999.1.1.1, port 99999): drift, not data
    bad = "2 123456789012 eni-0a1b2c3d 999.1.1.1 10.0.1.5 99999 22 6 20 4249 1789984800 1789984860 REJECT OK"
    fmt_name, parsed = parse_log(bad)
    assert fmt_name == "generic_inferred" and parsed["tracelog_parse"]["learned_drift"]["problems"]
    _, ev = normalized(bad)
    assert ev["src_endpoint"]["ip"] is None


def test_editing_an_approved_parser_takes_it_offline(db):
    ingest(lines(vpc_flow(60)))
    (fmt,) = formats(db)
    done = learn_and_approve(db, fmt["format_id"])
    line = vpc_flow(3, seed=5)[0]["line"]
    assert parse_log(line)[1]["tracelog_parse"]["verified"]
    src = next(s["id"] for s in done["spec"]["slots"] if s["role"] == "src_ip")
    dst = next(s["id"] for s in done["spec"]["slots"] if s["role"] == "dst_ip")
    edited = workflow.edit(done["id"], roles={src: "dst_ip", dst: "src_ip"}, reviewer="asha")
    assert edited["status"] == "candidate" and edited["approved_by"] is None
    assert parse_log(line)[0] == "generic_inferred"  # no longer applied until approved again
    assert workflow.approve(edited["id"], "ravi")["status"] == "approved"
    parsed = parse_log(line)[1]
    assert parsed["tracelog_parse"]["approved_by"] == "ravi"


def test_api_flow(db):
    from fastapi.testclient import TestClient
    from backend.main import app
    client = TestClient(app)
    ingest(lines(ssh_auth(40)))
    (fmt,) = client.get("/api/formats").json()
    detail = client.get(f"/api/formats/{fmt['format_id']}").json()
    assert detail["samples_shown"] and detail["parsed_now"][0]["parser"].startswith("generic")
    cand = client.post(f"/api/formats/{fmt['format_id']}/learn", json={"vendor": "OpenBSD", "product": "OpenSSH"}).json()
    assert cand["class_uid"] == 3002 and [s["role"] for s in cand["needs_review"]] == ["user"]
    r = client.post(f"/api/formats/parsers/{cand['id']}/approve", json={"approved_by": "asha"})
    assert r.status_code == 400 and r.json()["detail"]["needs_review"][0]["role"] == "user"
    r = client.post(f"/api/formats/parsers/{cand['id']}/approve",
                    json={"approved_by": "asha", "confirmed": [cand["needs_review"][0]["id"]]})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert client.post(f"/api/parsers/{cand['id']}/approve").status_code == 400  # not through the old gate
    assert client.post(f"/api/formats/parsers/{cand['id']}/reparse", json={}).json()["revised"] == 40
    assert any(p["format_type"] == "learned" for p in client.get("/api/parsers").json())
    for case in ssh_auth(10, seed=8):
        _, ev = normalized(case["line"])
        wrong, missed, _ = score(ev, case["truth"])
        assert wrong == [] and missed == []
