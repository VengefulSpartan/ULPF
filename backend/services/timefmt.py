"""
Reading timestamps without trying every format on every line.

A log source sends timestamps of one shape: "Sep 20 14:00:15", "2026-09-21T10:15:02Z",
"21/Sep/2026:10:15:02 +0530". Parsers here hold a list of candidate formats and try them in
order, so a line whose format sits near the end of the list costs a failed strptime for every
format before it - and strptime keeps only five compiled formats, so a long list thrashes that
cache as well.

parse_first remembers which format read a given *shape* of timestamp (digits folded to 9,
letters to a) and tries that one first, falling back to the full list if it does not fit. The
answer is the same; the work is one strptime per line instead of one per candidate format.
"""
from typing import Any, Callable, Dict, Optional, Tuple

_SHAPE = str.maketrans("0123456789"
                       "abcdefghijklmnopqrstuvwxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                       "9" * 10 + "a" * 26 + "A" * 26)
_MEMO: Dict[Tuple[Tuple[str, ...], str], Optional[str]] = {}
_MEMO_MAX = 8192
_UNSEEN = object()


def shape(text: str) -> str:
    return text.translate(_SHAPE)


def _remember(key, fmt: Optional[str]) -> None:
    if len(_MEMO) >= _MEMO_MAX:
        _MEMO.clear()
    _MEMO[key] = fmt


def parse_first(text: str, formats: Tuple[str, ...],
                attempt: Callable[[str], Any]) -> Optional[Tuple[str, Any]]:
    """
    (format, value) for the first format `attempt` accepts, or None when none of them fit.

    `attempt(fmt)` parses `text` with that format and raises ValueError when it does not fit,
    so each caller keeps its own rules (a year prepended for yearless formats, time zones).
    """
    key = (formats, text.translate(_SHAPE))
    remembered = _MEMO.get(key, _UNSEEN)
    if remembered is not _UNSEEN:
        if remembered is None:
            return None                      # nothing read this shape last time either
        try:
            return remembered, attempt(remembered)
        except ValueError:
            pass                             # two formats share this shape: fall back to the list
    for fmt in formats:
        try:
            value = attempt(fmt)
        except ValueError:
            continue
        _remember(key, fmt)
        return fmt, value
    _remember(key, None)
    return None


def clear() -> None:
    """Forget what was learned (for tests that change the format lists)."""
    _MEMO.clear()
