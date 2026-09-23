# Performance: what was measured, what was changed, what is left

Every number here comes from `scripts/benchmark.py`, which replays a mixed corpus (80 % lines
vendor packs know, 15 % formats with no pack, 5 % lines nothing parses; values vary per line)
through the real pipeline — decode, parse, normalise to OCSF 1.1.0, archive, hash-chain, store —
on a throwaway database.

```
python scripts/benchmark.py -n 100000 -b 1000 --read
```

Run it on your own hardware before quoting a figure. The figures below are from a small
2-vCPU container, which is the floor, not the ceiling.

## Before and after

100,000 events, batches of 1,000, same machine, same corpus:

| | before | after |
|---|---|---|
| Ingest, end to end | 1,263 events/s | **1,622 events/s** |
| Newest 50 events (Explorer page) | 105 ms | **9.5 ms** |
| Search the archive for an address | 120 ms | **3.2 ms** |
| Filter by IP | 110 ms | **2.7 ms** |
| Dashboard | 2,281 ms | **659 ms** |
| Verify the whole chain | 7,350 ms | **3,848 ms** |

At 20,000 events, where index maintenance costs less, ingestion runs at **2,711 events/s**
(before: 1,489).

Batch size matters: 200 lines per transaction gives 2,239 events/s, 1,000 gives 2,690, 2,000
gives 2,726 while doubling latency. The pipeline default is now 1,000, flushed every 0.5 s.

A sustained rate of 11,574 events/s is one billion events a day. Quote the rate your hardware
measures and the multiplication, not a round number.

## What was changed

**The chain head was read from SQLite once per line, twice over.** Every event ran
`SELECT ... FROM integrity_ledger ORDER BY sequence_num DESC LIMIT 1` in the ingest loop and
again inside `append_event`. A batch now reads the head once, under the same write lock, and
links its events in memory (`IntegrityLedger.chain_head` / `link` / `insert_links`). Same
sequence numbers, same hashes.

**Three inserts per line became three statements per batch.** `executemany` for `raw_logs`,
`normalized_events` and `integrity_ledger`, inside the one transaction that was already there.

**Each event was serialised three times.** The stored `normalized_json` is now the canonical
form the chain hashes, so it is built once, and `orjson` does it (`backend/services/jsonio.py`,
with a standard-library fallback that produces the same bytes — `tests/test_throughput.py`
checks that, because the canonical form is the hash preimage).

**Timestamps were parsed by trying every candidate format.** 6,000 lines cost 83,000 `strptime`
calls, which also thrashed the five-format cache inside `strptime` itself.
`backend/services/timefmt.py` remembers which format read a given *shape* of timestamp (digits
folded to 9, letters to a) and tries that one first, falling back to the full list. Parsing
dropped from 190 µs to 83 µs per line.

**Field lookup lower-cased every key of every line, per alias.** `find_first` searches a dozen
spellings of each field (src, srcip, source_ip, saddr, ...); 6,000 lines made 8.3 million
`str.lower()` calls. The parsed line now carries a lower-cased index built once
(`IndexedFields`), and the field names the generic parser analyses are cached.

**The strict OCSF form was built for every stored event, whether or not anything wanted it.**
`StoredEvent.ocsf` is now built when an output asks for it.

**The dashboard read and parsed the JSON of every event to say which parser read it.** Events
carry a `parser_pack` column (an index over what the event already says), backfilled by
migration and grouped with an index-only scan.

**The dashboard re-checked the same events against OCSF on every load.** Events never change
once written, so conformance is now checked incrementally: the first call checks the newest
2,000, later calls only what arrived since.

**Indexes.** Added: `normalized_events(raw_id)`, `raw_logs(source_id)`, and partial indexes over
current events for `sequence_num DESC`, `class_name`, `severity`, `category_name`, `parser_pack`.
Removed: a plain index on `superseded_by`, which is useless (almost every row is NULL) and which
the planner kept choosing — it cost the Explorer page 140 ms.

**Statistics.** Without them SQLite reads the newest 50 events by scanning and sorting every
event instead of walking the partial index backwards. `PRAGMA optimize` now runs every 25
batches, and the page count names its index explicitly.

**Search.** The archived lines are in an FTS5 index over `raw_logs` (no second copy of the text),
kept in step by triggers. Searching 100,000 lines for an address takes 3 ms instead of 330 ms.
It costs about a quarter of the ingest rate, so `SEARCH_INDEX=false` turns it off for a
deployment that only forwards. Free-text search reads the archived line; the boxes beside it
filter on the OCSF fields.

**Connections.** Each API call and each batch opened a new SQLite connection and re-ran the
pragmas; the code never closed them either. One connection per thread is kept, with a 64 MB page
cache and memory temp store.

## What was deliberately not changed

- **The hashed record.** Sequence numbers, the preimage `H(prev : seq : raw_hash : canonical_json)`
  and the canonical JSON are byte for byte what they were. `tests/test_throughput.py` verifies a
  batch produces the chain a line-at-a-time writer produced, and the chain still verifies.
- **What the parsers decide.** `scripts/evaluate_unseen_formats.py` still scores 85 correct,
  18 missed, **0 wrong** over the 103 fields in 13 unseen formats.
- **Pydantic validation** on the event model, which is what stops a malformed event reaching a
  SIEM. Bypassing it would buy about 10 %.

## The next levers, measured

1. **Write volume.** A stored event is about 3.2 KB: 2.1 KB of canonical JSON, 0.9 KB of
   `unmapped_json` that repeats a section of it, and 0.2 KB of raw line. With indexes and the
   full-text index the database grows about 6 KB per event, and that write amplification is why
   throughput falls from 2,711 events/s at 20k events to 1,622 at 100k. Dropping the duplicated
   column is the single biggest remaining win and is a schema change, not a tuning change.
2. **More cores.** The pipeline is one process. Sharding by source, with one chain per shard, is
   the way to use the rest of the machine; the chain writer only ever handles 32-byte digests.
3. **Columnar parsing.** Profiling says parsing is 13–22 % of the time and normalisation the
   larger share. Porting the vendor packs to Polars expressions (their regexes use no lookaheads,
   so they port) is the next step after that, and is a rewrite to be done with the equivalence
   tests in place, not before a deadline.
