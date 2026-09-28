#!/usr/bin/env python3
"""
Check a TRACELOG evidence bundle. Copied into every bundle as verify.py.

    python verify.py              (the folder this file is in)
    python verify.py <folder>

Needs only Python 3.8 or later. What it checks, in this order:

1. every file listed in SHA256SUMS still has the SHA-256 written there;
2. each raw line's SHA-256 is the one recorded when TRACELOG received it;
3. each chain record hash is SHA-256(previous record hash : sequence number : raw line hash :
   stored event), so the event and the raw line are the ones that were chained;
4. records with consecutive sequence numbers link to each other;
5. for records sealed in a signed checkpoint: the Merkle inclusion proof leads from the record to
   the checkpoint's root (RFC 9162), and the checkpoint's hash matches its signed text;
6. the node's and the witnesses' signatures on those checkpoints, when the `cryptography`
   package is installed (pip install cryptography); without it, step 6 is reported as skipped.

It prints one line per check and exits with 0 when everything that could be checked holds.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion(index, tree_size, leaf, path, root) -> bool:
    """RFC 9162 section 2.1.3.2."""
    if not 0 <= index < tree_size:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def check_signature(sig) -> object:
    """True/False, or None when this Python cannot check the algorithm."""
    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return None
    raw, s, message = base64.b64decode(sig["public_key"]), base64.b64decode(sig["sig"]), sig["_message"]
    try:
        if sig["alg"] == "ed25519":
            from cryptography.hazmat.primitives.asymmetric import ed25519
            ed25519.Ed25519PublicKey.from_public_bytes(raw).verify(s, message)
        elif sig["alg"] == "ml-dsa-65":
            try:
                from cryptography.hazmat.primitives.asymmetric import mldsa
            except ImportError:
                return None
            mldsa.MLDSA65PublicKey.from_public_bytes(raw).verify(s, message)
        else:
            return None
        return True
    except (InvalidSignature, ValueError):
        return False


def main(folder: Path) -> int:
    manifest_path = folder / "manifest.json"
    if not manifest_path.exists():
        print(f"No manifest.json in {folder}: is this a TRACELOG evidence bundle?")
        return 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures, skipped = [], []

    def ok(label, good, detail=""):
        print(f"  [{'OK' if good else 'FAIL'}] {label}{(': ' + detail) if detail else ''}")
        if not good:
            failures.append(label)

    print(f"TRACELOG evidence bundle {manifest['bundle']['id']}")
    print(f"manifest.json SHA-256: {sha256(manifest_path.read_bytes())}")

    print("1. Files")
    sums = folder / "SHA256SUMS"
    if sums.exists():
        for line in sums.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            digest, name = line.split(None, 1)
            name = name.lstrip("*")
            f = folder / name
            ok(name, f.exists() and sha256(f.read_bytes()) == digest,
               "" if f.exists() else "missing")
    else:
        ok("SHA256SUMS present", False)

    records = manifest["records"]
    checkpoints = {int(k): v for k, v in (manifest.get("checkpoints") or {}).items()}
    print(f"2-4. Records ({len(records)})")
    previous = None
    for rec in records:
        seq = rec["sequence_num"]
        raw = (folder / rec["raw_file"]).read_bytes()
        event = (folder / rec["event_file"]).read_text(encoding="utf-8").strip()
        raw_ok = sha256(raw) == rec["raw_sha256"]
        preimage = f"{rec['prev_hash']}:{seq}:{rec['raw_sha256']}:{event}"
        record_ok = sha256(preimage.encode("utf-8")) == rec["record_hash"]
        link_ok = previous is None or previous["sequence_num"] + 1 != seq or rec["prev_hash"] == previous["record_hash"]
        ok(f"record #{seq}", raw_ok and record_ok and link_ok,
           "; ".join(x for x, bad in (("raw line changed", not raw_ok), ("event or chain record changed", not record_ok),
                                       ("does not link to the record before it", not link_ok)) if bad))
        previous = rec

    print(f"5. Merkle proofs against signed checkpoints ({len(checkpoints)} checkpoint(s))")
    for idx, cp in sorted(checkpoints.items()):
        ok(f"checkpoint #{idx} hash", sha256(cp["body"].encode("utf-8")) == cp["checkpoint_hash"])
    unsealed = 0
    for rec in records:
        proof = rec.get("proof")
        if not proof:
            unsealed += 1
            continue
        cp = checkpoints[int(proof["checkpoint"])]
        body = json.loads(cp["body"])
        leaf = hashlib.sha256(b"\x00" + f"{rec['sequence_num']}:{rec['record_hash']}".encode("ascii")).digest()
        # the tree size and the position come from the signed checkpoint, not from the proof alone
        in_range = body["first_seq"] <= rec["sequence_num"] <= body["last_seq"]
        position = rec["sequence_num"] - body["first_seq"] if body["size"] == body["last_seq"] - body["first_seq"] + 1 \
            else proof["leaf_index"]
        good = in_range and proof["tree_size"] == body["size"] and proof["leaf_index"] == position and \
            verify_inclusion(proof["leaf_index"], body["size"], leaf, [bytes.fromhex(h) for h in proof["path"]],
                             bytes.fromhex(body["merkle_root"]))
        ok(f"record #{rec['sequence_num']} is in checkpoint #{proof['checkpoint']}", good)
    if unsealed:
        print(f"  [--] {unsealed} record(s) were not yet in a signed checkpoint when the bundle was made")

    print("6. Signatures")
    for idx, cp in sorted(checkpoints.items()):
        for sig in cp.get("signatures", []):
            who = "node" if sig.get("role") == "node" else f"witness {sig.get('name')}"
            result = check_signature(dict(sig, _message=cp["body"].encode("utf-8")))
            if result is None:
                skipped.append(f"checkpoint #{idx} {who} {sig.get('alg')}")
                print(f"  [--] checkpoint #{idx}, {who}, {sig.get('alg')}: not checked (pip install cryptography)")
            else:
                ok(f"checkpoint #{idx}, {who}, {sig.get('alg')} (key {sig.get('key_id')})", result)

    print()
    if failures:
        print(f"RESULT: {len(failures)} check(s) FAILED. The bundle or the records in it were changed after export.")
        return 1
    print("RESULT: every check that could be run passed." + (f" {len(skipped)} signature check(s) skipped."
                                                              if skipped else ""))
    return 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    sys.exit(main(target))
