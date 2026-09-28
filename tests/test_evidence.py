"""
Proof beyond the hash chain: signed checkpoints with witnesses, evidence bundles anyone can check,
and CERT-In reporting.

- the Merkle trees are RFC 9162's (the reference roots of RFC 6962's test vectors);
- the collector seals full windows as it writes and the rest on request, signing with Ed25519 and
  ML-DSA-65; a record changed after sealing no longer matches its checkpoint;
- an insider who changes a record, recomputes the chain and re-signs the checkpoints passes the
  chain check and the node's own signatures, and is caught by the witnesses, which refuse to sign a
  different checkpoint with the same number; restoring puts every hash back;
- an evidence bundle's own verify.py passes on the bundle as exported and names the record when
  one byte of a raw line is changed;
- the CERT-In draft suggests incident types from the evidence, counts the 6 hours from the first
  detection received, and in CERT-In mode nothing is deleted.
"""
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.services.ingestion.stream import InboundRecord, StreamIngestor
from backend.services.integrity import checkpoints, merkle, signing
from backend.services.integrity.ledger import IntegrityLedger
from backend.witness import create_app as create_witness
from tests.test_vendor_packs import ASA_DENY, FORTI_IPS, FORTI_TRAFFIC, PAN_TRAFFIC, SURICATA

ROOT = Path(__file__).resolve().parents[1]
LINES = [FORTI_TRAFFIC, FORTI_IPS, PAN_TRAFFIC, ASA_DENY, SURICATA]


def _ingest(lines, transport="syslog-udp"):
    StreamIngestor().ingest([InboundRecord(raw=l.encode(), transport=transport, input_name="t") for l in lines])


@pytest.fixture
def witnesses(tmp_path, monkeypatch):
    """Two witnesses, each with its own keys and records, reached through checkpoints._http."""
    apps = {f"http://w{i}": TestClient(create_witness(f"witness-{i}", tmp_path / f"w{i}")) for i in (1, 2)}

    def call(method, url, **kwargs):
        kwargs.pop("timeout", None)
        for base, client in apps.items():
            if url.startswith(base):
                return client.request(method, url[len(base):], **kwargs)
        raise ConnectionError(url)
    monkeypatch.setattr(checkpoints, "_http", call)
    monkeypatch.setattr(checkpoints.settings, "WITNESS_URLS", ",".join(apps))
    checkpoints._signed_through.clear()
    return apps


@pytest.fixture
def correlated(isolated_db, monkeypatch):
    """The sample data, correlated around 10.0.1.15, all in the test database."""
    import backend.api.correlation as api_correlation
    import backend.services.correlation.engine as engine
    from backend.main import create_app
    monkeypatch.setattr(engine, "db", isolated_db)
    monkeypatch.setattr(api_correlation, "db", isolated_db)
    client = TestClient(create_app("all"))
    client.post("/api/ingest/seed-samples")
    return client, engine.CorrelationEngine.run_correlation(pivot_ip="10.0.1.15")


# ------------------------------------------------------------------ Merkle trees
def test_merkle_roots_are_rfc_6962s_reference_values():
    inputs = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43", b"\x50\x51\x52\x53\x54\x55\x56\x57",
              bytes(range(0x60, 0x70))]
    leaves = [merkle.leaf_hash(x) for x in inputs]
    assert merkle.root(leaves[:1]).hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert merkle.root(leaves[:3]).hex() == "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"
    assert merkle.root(leaves).hex() == "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"


def test_every_leaf_has_a_proof_and_no_other_leaf_fits_it():
    for n in list(range(1, 34)) + [100, 1000]:
        leaves = [merkle.leaf_hash(merkle.leaf_data(i + 1, f"{i:064x}")) for i in range(n)]
        root = merkle.root(leaves)
        for i in range(0, n, max(1, n // 40)):
            path = merkle.inclusion_path(i, leaves)
            assert merkle.verify_inclusion(i, n, leaves[i], path, root)
            assert n == 1 or not merkle.verify_inclusion(i, n, leaves[(i + 1) % n], path, root)


# ------------------------------------------------------------------ sealing and signatures
def test_full_windows_are_sealed_as_they_are_written_and_the_rest_on_request(isolated_db, monkeypatch):
    monkeypatch.setattr(checkpoints.settings, "CHECKPOINT_SIZE", 4)
    _ingest(LINES * 2)                                        # 10 records: #1-4 and #5-8 sealed inline
    with isolated_db.get_connection() as conn:
        spans = [tuple(r) for r in conn.execute("SELECT first_seq, last_seq FROM checkpoints ORDER BY idx")]
    assert spans == [(1, 4), (5, 8)]
    assert [(m["first_seq"], m["last_seq"]) for m in checkpoints.seal(force=True)] == [(9, 10)]
    assert checkpoints.seal(force=True) == []                 # nothing left to seal

    v = checkpoints.verify(ask_witnesses=False)
    assert v["ok"] and v["checkpoints"] == 3 and v["sealed_records"] == 10 and v["unsealed_records"] == 0
    assert set(v["algorithms"]) == set(signing.algorithms()) and "ed25519" in v["algorithms"]
    with isolated_db.get_connection() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM checkpoints ORDER BY idx")]
    assert rows[0]["prev_hash"] == checkpoints.GENESIS
    assert [r["prev_hash"] for r in rows[1:]] == [r["checkpoint_hash"] for r in rows[:-1]]   # their own chain
    keys = isolated_db.db_path.parent / "keys"
    assert (keys / "node-ed25519.pem").is_file() and (keys / "node-ed25519.pem").stat().st_mode & 0o077 == 0


def test_a_record_changed_after_sealing_no_longer_matches_its_checkpoint(isolated_db):
    _ingest(LINES)
    checkpoints.seal(force=True)
    with isolated_db.get_connection() as conn:
        conn.execute("UPDATE integrity_ledger SET record_hash = ? WHERE sequence_num = 3", ("f" * 64,))
        conn.commit()
    v = checkpoints.verify(ask_witnesses=False)
    assert not v["ok"] and "Merkle root no longer matches" in v["problems"][0]["problem"]


def test_an_inclusion_proof_leads_from_a_record_to_the_signed_root(isolated_db):
    _ingest(LINES * 3)
    checkpoints.seal(force=True)
    p = checkpoints.proof(7)
    body = json.loads(p["checkpoint"]["body"])
    assert merkle.verify_inclusion(p["leaf_index"], p["tree_size"], merkle.leaf_hash(p["leaf"].encode()),
                                   [bytes.fromhex(h) for h in p["path"]], bytes.fromhex(body["merkle_root"]))
    node = [s for s in p["checkpoint"]["signatures"] if s["role"] == "node"]
    assert all(signing.verify(s["alg"], s["public_key"], p["checkpoint"]["body"].encode(), s["sig"]) for s in node)


# ------------------------------------------------------------------ witnesses
def test_witnesses_countersign_and_agree(isolated_db, witnesses):
    _ingest(LINES * 2)
    checkpoints.seal(force=True)
    report = checkpoints.cosign_pending()
    assert all(w["reachable"] and w["error"] is None and w["signed"] == 1 for w in report.values())
    v = checkpoints.verify()
    assert v["ok"], v["problems"]
    assert [(w["witness"], w["agree"], w["differ"]) for w in v["witnesses"]] == [("witness-1", 1, []), ("witness-2", 1, [])]
    assert checkpoints.cosign_pending()["http://w1"]["signed"] == 0      # nothing left to sign


def test_an_insider_who_rewrites_and_re_signs_is_caught_by_the_witnesses_only(isolated_db, witnesses, monkeypatch):
    monkeypatch.setattr(checkpoints.settings, "CHECKPOINT_SIZE", 4)
    _ingest(LINES * 2)
    checkpoints.seal(force=True)
    checkpoints.cosign_pending()
    with isolated_db.get_connection() as conn:
        before = {r[0]: r[1] for r in conn.execute("SELECT sequence_num, record_hash FROM integrity_ledger")}

    done = checkpoints.rewrite_history(3, "disposition", "tampered")
    assert done["records_rehashed"] == 8 and done["checkpoints_resigned"] == 3
    assert IntegrityLedger.verify_chain().is_valid                         # the chain alone is fooled
    assert checkpoints.verify(ask_witnesses=False)["ok"]                   # so are the node's own signatures
    refused = checkpoints.cosign_pending()
    assert all("#1" in w["error"] and "refusing a different one" in w["error"] for w in refused.values())
    v = checkpoints.verify()
    assert not v["ok"] and v["problems"][0]["index"] == 1
    assert "signed a different checkpoint #1" in v["problems"][0]["problem"]
    assert checkpoints.seal(force=False) == []                            # nothing sealed during the demonstration

    checkpoints.restore_history()
    with isolated_db.get_connection() as conn:
        assert {r[0]: r[1] for r in conn.execute("SELECT sequence_num, record_hash FROM integrity_ledger")} == before
    assert IntegrityLedger.verify_chain().is_valid and checkpoints.verify()["ok"]


def test_a_witness_signs_only_the_next_checkpoint_of_a_history_it_knows(tmp_path):
    client = TestClient(create_witness("w", tmp_path / "w"))
    node = signing.Signer("node", tmp_path / "keys")
    other = signing.Signer("other", tmp_path / "keys")

    def cp(index, prev, root="a" * 64, signer=node, log="log-1"):
        body = json.dumps({"v": 1, "type": "tracelog-checkpoint", "log_id": log, "index": index, "first_seq": index,
                           "last_seq": index, "size": 1, "merkle_root": root, "prev_checkpoint": prev,
                           "node_key_id": signer.key_id, "sealed_at": "2026-09-28T00:00:00+00:00"}, sort_keys=True)
        return body, client.post("/witness/cosign", json={"body": body, "signatures": signer.sign(body.encode())})

    import hashlib
    b1, r = cp(1, "0" * 64)
    assert r.status_code == 200 and len(r.json()["signatures"]) == len(signing.algorithms())
    h1 = hashlib.sha256(b1.encode()).hexdigest()
    assert cp(1, "0" * 64)[1].status_code == 200                          # the same checkpoint again: fine
    assert cp(1, "0" * 64, root="b" * 64)[1].status_code == 409            # a different #1: never
    assert cp(3, h1)[1].status_code == 409                                 # a gap
    assert cp(2, "c" * 64)[1].status_code == 409                           # does not extend #1
    assert cp(2, h1, signer=other)[1].status_code == 409                   # another node key for this log
    assert cp(2, h1)[1].status_code == 200
    body, _ = cp(1, "0" * 64, log="log-2")
    forged = client.post("/witness/cosign", json={"body": body.replace("log-2", "log-3"),
                                                  "signatures": node.sign(body.encode())})
    assert forged.status_code == 400                                       # the signature is not over this body
    info = client.get("/witness/info").json()
    assert {l["log_id"]: l["last_index"] for l in info["logs"]} == {"log-1": 2, "log-2": 1}


# ------------------------------------------------------------------ evidence bundles
def _bundle(isolated_db, sequences, **kw):
    from backend.services.evidence import bundle
    made = bundle.build(sequences, case={"prepared_by": "A. Analyst", "case_ref": "CR-17"}, **kw)
    return made, zipfile.ZipFile(io.BytesIO(made["zip"]))


def test_an_evidence_bundle_checks_out_with_its_own_verify_script(isolated_db, tmp_path, monkeypatch):
    monkeypatch.setattr(checkpoints.settings, "CHECKPOINT_SIZE", 4)
    _ingest([l + "\r\n" for l in LINES * 2], transport="syslog-tcp")
    made, z = _bundle(isolated_db, [2, 3, 9])
    names = {n.split("/", 1)[1] for n in z.namelist()}
    assert {"manifest.json", "verify.py", "README.txt", "SHA256SUMS", "certificate-s63.pdf", "raw/00000002.log",
            "events/00000009.json"} <= names
    manifest = json.loads(z.read(f"{made['filename'][:-4]}/manifest.json"))
    assert made["checks"]["raw_hash_matches"] == made["checks"]["record_hash_matches"] == 3
    assert made["checks"]["in_signed_checkpoint"] == 2                     # #9 and #10 were not sealed yet
    assert manifest["records"][0]["line_terminator_removed"] == "CRLF"
    assert z.read(f"{made['filename'][:-4]}/certificate-s63.pdf")[:5] == b"%PDF-"

    z.extractall(tmp_path)
    folder = tmp_path / made["filename"][:-4]
    run = subprocess.run([sys.executable, str(folder / "verify.py")], capture_output=True, text=True, encoding="utf-8")
    assert run.returncode == 0, run.stdout
    assert "record #2 is in checkpoint #1" in run.stdout and "RESULT: every check" in run.stdout

    raw = folder / "raw" / "00000003.log"
    raw.write_bytes(raw.read_bytes()[:-1] + b"X")
    run = subprocess.run([sys.executable, str(folder / "verify.py")], capture_output=True, text=True, encoding="utf-8")
    assert run.returncode == 1 and "[FAIL] record #3: raw line changed" in run.stdout


def test_the_raw_file_is_the_bytes_the_device_sent(isolated_db):
    latin = "date=2026-09-20 msg=caf\xe9 action=deny".encode("latin-1")     # not UTF-8
    StreamIngestor().ingest([InboundRecord(raw=latin + b"\n", transport="syslog-udp", input_name="t")])
    made, z = _bundle(isolated_db, [1])
    assert z.read(f"{made['filename'][:-4]}/raw/00000001.log") == latin


def test_evidence_for_a_correlated_incident_through_the_api(correlated):
    client, incident = correlated
    r = client.get("/api/evidence/bundle.zip", params={"incident_id": incident.incident_id})
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    manifest = json.loads(next(z.read(n) for n in z.namelist() if n.endswith("manifest.json")))
    assert [x["sequence_num"] for x in manifest["records"]] == sorted(f.sequence_num for f in incident.observed_facts)
    assert manifest["bundle"]["scope"]["incident_id"] == incident.incident_id
    assert client.get("/api/evidence/bundle.zip", params={"seq": 999}).status_code == 404


# ------------------------------------------------------------------ CERT-In
def test_incident_types_are_suggested_from_the_evidence():
    from backend.services.compliance.certin_types import suggest_types
    sweep = {"observed_facts": [{"sequence_num": 4, "fact_description": "Signature: 'ET SCAN Nmap Scripting Engine'"}],
             "inferred_relationships": [{"relationship_type": "PORT_SWEEP"}]}
    assert [s["code"] for s in suggest_types(sweep)] == ["i"]
    login = {"observed_facts": [{"sequence_num": 1, "fact_description": "Authentication: allow. User: 'bob'."}]}
    assert "iii" in [s["code"] for s in suggest_types(login)]
    assert suggest_types({"observed_facts": [{"sequence_num": 1, "fact_description": "Network Activity: allow"}]}) == []


def test_the_cert_in_draft_counts_six_hours_from_the_first_detection_received(correlated):
    from datetime import datetime, timedelta
    from backend.services.compliance import certin
    client, incident = correlated
    r = certin.draft_report(incident.incident_id, org={"organisation": "Example Ltd"})
    noticed, due = (datetime.fromisoformat(r["incident"][k]) for k in ("noticed_at", "report_by"))
    assert due - noticed == timedelta(hours=6) and r["incident"]["noticed_basis"] == "the first detection TRACELOG received"
    assert {t["code"] for t in r["incident"]["types"]} >= {"iii"}
    assert "198.51.100.22" in r["indicators"]["external_addresses"]        # a documentation range stands for public
    assert "10.0.1.15" in r["affected"]["internal_addresses"]
    assert r["evidence"]["records_matching_their_hashes"] == r["evidence"]["records"] == len(incident.observed_facts)
    assert r["reporting_entity"]["organisation"] == "Example Ltd" and r["report_to"] == "incident@cert-in.org.in"
    pdf = client.get("/api/compliance/certin/report.pdf", params={"incident_id": incident.incident_id})
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"
    assert client.get("/api/compliance/certin/report.json", params={"incident_id": "nope"}).status_code == 404


def test_in_cert_in_mode_stored_events_cannot_be_deleted(monkeypatch):
    from backend.services.compliance import certin
    monkeypatch.setattr(certin.settings, "CERTIN_MODE", True)
    assert not certin.deletion_allowed()
    import ast
    tree = ast.parse((ROOT / "frontend" / "views" / "settings_page.py").read_text(encoding="utf-8"))
    reset = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_reset")
    first = reset.body[0]                                       # refused before anything is deleted
    assert isinstance(first, ast.If) and ast.unparse(first.test) == "settings.CERTIN_MODE"
    assert isinstance(first.body[-1], ast.Return)


def test_retention_status_reports_what_the_archive_holds(isolated_db):
    from backend.services.compliance import certin
    assert certin.retention_status()["lines_kept"] == 0
    _ingest(LINES)
    s = certin.retention_status()
    assert s["lines_kept"] == 5 and s["retention_days"] == 180 and s["days_held"] < 1 and not s["full_window_held"]
    assert s["successful_events"] + s["failed_or_blocked_events"] <= 5
