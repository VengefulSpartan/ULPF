"""
Merkle trees over chain records, as RFC 9162 (Certificate Transparency 2.0) defines them.

A checkpoint (checkpoints.py) covers a run of consecutive chain records with one Merkle root.
The root is 32 bytes, however many records it covers, and any one record can be shown to be
under it with log2(n) hashes (an inclusion proof) without revealing the other records.

The leaf for a chain record is the text "<sequence number>:<record hash>". The record hash
already covers the raw line's SHA-256, the event and the previous record, so the root covers
all of them. Leaves and inner nodes are hashed with different prefixes (0x00 and 0x01), as RFC
9162 requires, so a leaf can never be passed off as an inner node.

Only the standard library is used: the evidence bundle's verify.py carries a copy of
`verify_inclusion` and runs on any Python 3 without installing anything.
"""
import hashlib
from typing import List, Sequence


def leaf_data(sequence_num: int, record_hash: str) -> bytes:
    return f"{sequence_num}:{record_hash}".encode("ascii")


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two smaller than n (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(leaves: Sequence[bytes]) -> bytes:
    """MTH(D[n]) of RFC 9162 section 2.1.1, over leaf hashes (not leaf data)."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    level: List[bytes] = list(leaves)
    return _root(level)


def _root(hashes: List[bytes]) -> bytes:
    n = len(hashes)
    if n == 1:
        return hashes[0]
    k = _split(n)
    return node_hash(_root(hashes[:k]), _root(hashes[k:]))


def inclusion_path(index: int, leaves: Sequence[bytes]) -> List[bytes]:
    """PATH(m, D[n]) of RFC 9162 section 2.1.3.1: the hashes that lead from leaf `index` to the root."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(f"leaf {index} is not in a tree of {n}")
    return _path(index, list(leaves))


def _path(m: int, hashes: List[bytes]) -> List[bytes]:
    n = len(hashes)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return _path(m, hashes[:k]) + [_root(hashes[k:])]
    return _path(m - k, hashes[k:]) + [_root(hashes[:k])]


def verify_inclusion(index: int, tree_size: int, leaf: bytes, path: Sequence[bytes], expected_root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2: does `path` lead from the leaf hash at `index` to `expected_root`?"""
    if not 0 <= index < tree_size:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root
