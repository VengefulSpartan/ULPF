"""
Signing keys for checkpoints: the collector's own, and each witness's.

Every signer holds an Ed25519 key and, when the installed `cryptography` supports it (version
47 and later), an ML-DSA-65 key as well (FIPS 204, a signature that a quantum computer is not
known to break). A checkpoint is signed with both; each signature says which algorithm made it,
so a verifier checks what it can and says which ones it could not check. Replacing or adding an
algorithm later does not change anything already signed.

Keys are created on first use in a directory next to the database (`<database folder>/keys`,
or TRACELOG_KEY_DIR), readable by the owner only. They are never written anywhere else and
never committed: data/keys/ is in .gitignore. A key identifies itself by the first 16 hex
digits of the SHA-256 of its public key.
"""
import base64
import hashlib
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("tracelog.signing")

ED25519 = "ed25519"
ML_DSA_65 = "ml-dsa-65"

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - requirements.txt installs it; verify.py runs without it
    HAVE_CRYPTO = False

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
    mldsa.MLDSA65PrivateKey.generate().sign(b"probe")   # the bundled OpenSSL may lack it
    HAVE_ML_DSA = True
except Exception:
    HAVE_ML_DSA = False


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def algorithms() -> List[str]:
    """What this installation can sign and verify."""
    if not HAVE_CRYPTO:
        return []
    return [ED25519] + ([ML_DSA_65] if HAVE_ML_DSA else [])


class Signer:
    """One signer's keys, loaded from `directory` or created there on first use."""

    def __init__(self, name: str, directory: Path):
        if not HAVE_CRYPTO:
            raise RuntimeError("signing needs the 'cryptography' package: pip install -r requirements.txt")
        self.name = name
        self.directory = Path(directory)
        self._keys = {ED25519: self._load(ED25519)}
        if HAVE_ML_DSA:
            self._keys[ML_DSA_65] = self._load(ML_DSA_65)

    # ---------------------------------------------------------------- keys on disk
    def _path(self, alg: str) -> Path:
        return self.directory / f"{self.name}-{alg}.pem"

    def _load(self, alg: str):
        path = self._path(alg)
        if path.exists():
            return serialization.load_pem_private_key(path.read_bytes(), password=None)
        key = ed25519.Ed25519PrivateKey.generate() if alg == ED25519 else mldsa.MLDSA65PrivateKey.generate()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:   # a mounted Windows folder: permissions are the host's business
            pass
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        logger.info("created %s signing key %s", alg, path)
        return key

    # ---------------------------------------------------------------- use
    def public_keys(self) -> List[Dict[str, str]]:
        out = []
        for alg, key in self._keys.items():
            raw = key.public_key().public_bytes_raw()
            out.append({"alg": alg, "key_id": key_id(raw), "public_key": b64(raw)})
        return out

    @property
    def key_id(self) -> str:
        """The Ed25519 key's id: what names this signer."""
        return key_id(self._keys[ED25519].public_key().public_bytes_raw())

    def sign(self, message: bytes) -> List[Dict[str, str]]:
        """One signature per algorithm, each with the public key that checks it."""
        out = []
        for alg, key in self._keys.items():
            raw = key.public_key().public_bytes_raw()
            out.append({"alg": alg, "key_id": key_id(raw), "public_key": b64(raw), "sig": b64(key.sign(message))})
        return out


def verify(alg: str, public_key_b64: str, message: bytes, sig_b64: str) -> Optional[bool]:
    """True or False; None when this installation cannot check that algorithm."""
    if not HAVE_CRYPTO or alg not in algorithms():
        return None
    try:
        raw = base64.b64decode(public_key_b64)
        sig = base64.b64decode(sig_b64)
        if alg == ED25519:
            ed25519.Ed25519PublicKey.from_public_bytes(raw).verify(sig, message)
        else:
            mldsa.MLDSA65PublicKey.from_public_bytes(raw).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_all(signatures: List[Dict[str, str]], message: bytes) -> Dict[str, Optional[bool]]:
    """{alg: result} for a signer's signatures over `message`."""
    return {s.get("alg", "?"): verify(s.get("alg", ""), s.get("public_key", ""), message, s.get("sig", ""))
            for s in signatures}
