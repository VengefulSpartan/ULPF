# 2. What "lossless" means: the bytes received, and a hash of those bytes

Status: accepted, 24 September 2026.

## Context

The problem statement's first expected solution is "preserve complete raw event data without
information loss". Probing the build on 24 September found three ways it was not true:

- **File uploads replaced bytes.** The upload endpoint decoded the file with `errors="replace"`, so
  any byte that was not valid UTF-8 became U+FFFD. A line containing `caf\xe9` was stored as
  `caf�`, and the original byte could not be recovered by any means.
- **The API stripped whitespace** from the start and end of a line before storing it.
- **The hash did not prove the bytes received.** Streamed lines were stored so their bytes could be
  rebuilt, but `raw_hash` was SHA-256 of the decoded text's UTF-8 form. For a line that was not
  valid UTF-8 that is a hash of a re-encoding, not of what the device sent.

Uploads and API lines also went through a separate writer from streamed ones, so the three paths
could — and did — disagree about what preservation meant.

## Decision

Every line, whichever way it arrives, goes through the one writer (`stream.StreamIngestor`), and
that writer keeps:

1. **The line's bytes, exactly.** Decoded as UTF-8 when they are valid UTF-8, otherwise as Latin-1,
   which maps every byte to one character. The encoding is stored, so
   `raw_text.encode(raw_encoding)` is always the original bytes.
2. **The one line terminator the transport added**, in `raw_logs.raw_framing` (`LF`, `CRLF` or
   empty). It is framing rather than event content — a syslog datagram, a line in a file — but it
   is recorded, so the bytes *as they arrived* can be rebuilt as well. Exactly one terminator is
   removed; a second one, or a CR on its own, stays in the line. A line that itself ends in CR, sent
   with an LF after it, is indistinguishable from CRLF on the wire and rebuilds identically.
3. **A hash of the bytes received**: `raw_hash = SHA-256(line bytes)`, marked `raw_hash_of = 'bytes'`.

Blank and whitespace-only lines are not events and are not stored. Everything else is — including
lines starting with `#`, which the upload path used to drop and which are often a format's own
header (`#Fields:` in W3C logs, Zeek's `#fields`).

## Consequences

**Older rows keep verifying.** Rows written before this decision have `raw_hash_of` NULL and a hash
of the text's UTF-8 form. The verifier recomputes each row by the rule it was written under
(`Hasher.stored_raw_hash`). For any line that was valid UTF-8 — nearly all of them — the two rules
give the same hash, so nothing about those rows changes. Tampering with a stored byte is caught under
either rule.

**Anyone can check a line without trusting us.** `/api/events/{id}` returns the text, its encoding,
its framing and its hash, and says whether they agree; `SHA-256(raw_text.encode(raw_encoding))` is
the hash, and adding the framing back gives the bytes as they arrived.

**Uploads got faster.** They are written a batch per transaction instead of a transaction per line.

**What "exact" does not cover.** For Splunk HEC *event* requests, the event arrives as a value inside
a JSON envelope: a string event is kept verbatim; an object event is kept as that object serialised
with its keys in the order sent and non-ASCII characters as characters, because the JSON parser does
not preserve the original whitespace. A HEC body that is not UTF-8 is refused with HEC's "invalid data
format" error rather than accepted with bytes replaced, so the sender keeps it. Raw HEC
(`/services/collector/raw`), OTLP bodies and every syslog, file and Kafka input keep the bytes
exactly.

## References

- `backend/services/ingestion/stream.py` — `split_framing`, `decode_body`, the writer
- `backend/services/integrity/hasher.py` — `stored_raw_hash`
- `tests/test_lossless.py` — every path, every kind of byte, both hash rules, tampering
