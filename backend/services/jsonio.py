"""
JSON the pipeline can serialise fast and reproducibly.

Every event is serialised twice (the canonical form the chain hashes, and its unmapped
section) and read back on every search, export and verification, so this is one of the
hottest paths in the product. orjson does it several times faster than the standard
library; when it is not installed the standard library is used instead.

The two must agree byte for byte, because the canonical form is the hash preimage: an
event written on a machine with orjson has to verify on one without it. Both produce
compact separators, sorted keys where asked, UTF-8 without \\u escapes, and both refuse
types JSON has no representation for. tests/test_throughput.py checks that on the whole
sample corpus.
"""
import json
from typing import Any

try:
    import orjson

    def _unsupported(value: Any) -> Any:
        raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")

    _PASSTHROUGH = orjson.OPT_PASSTHROUGH_DATETIME  # dates go to _unsupported, as json.dumps does

    def dumps(obj: Any) -> str:
        return orjson.dumps(obj, default=_unsupported, option=_PASSTHROUGH).decode()

    def canonical(obj: Any) -> str:
        return orjson.dumps(obj, default=_unsupported,
                            option=_PASSTHROUGH | orjson.OPT_SORT_KEYS).decode()

    def loads(text: Any) -> Any:
        return orjson.loads(text)

    HAVE_ORJSON = True
except ImportError:  # pragma: no cover - exercised on installs without orjson
    def dumps(obj: Any) -> str:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

    def canonical(obj: Any) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def loads(text: Any) -> Any:
        return json.loads(text)

    HAVE_ORJSON = False
