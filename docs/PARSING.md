# Parsing log formats TRACELOG has never seen

A parser that meets an unfamiliar format has two ways to fail. It can leave fields empty,
which a SOC notices and fixes. Or it can fill them with the wrong values, a destination
address as the source or a debug message marked Critical, which a SIEM then trusts and
correlates. The second failure is the dangerous one. TRACELOG handles unknown formats in
four layers, and the first rule overrides everything else: **a field is empty rather than
wrong**.

```
line ──► vendor pack ──► values valid? ──no──► learned parser ──► values valid? ──no──► generic parser
            │ (12 packs)      │ yes                 │ (approved       │ yes              (evidence only,
            │                 ▼                     │  in Studio)     ▼                   unverified)
            │              event                    │              event (verified)          │
            └── none claims the line ───────────────┴── none claims it ─────────────────────┘
                                                                                             ▼
                                                            format registry: count, samples, devices, drift
                                                                                             ▼
                                                  Parser Studio: learn from samples ► review ► approve ► re-parse
```

## Layer 1: never confidently wrong

`backend/services/parsing/inference.py` is the generic parser for lines no pack or learned
parser claims. It fills a field only when it has evidence for both what the field means
and that its value is valid:

| Evidence | Examples |
|---|---|
| The key names the field | `source-ip`, `srcIP`, `ip_client`, `SRC`, `event.clientip` all mean the source address; `management_ip_address` and `srcNAT` are skipped |
| The value is valid for the field | an address field must hold an IP, a port 0 to 65535, a protocol a protocol name or IANA number, a time must parse and be plausible |
| The line says the direction | `a:p -> b:q`, `from a to b` |
| The syslog header | timestamp, host, and the RFC 5424 severity, where 0 is emergency and 7 is debug |

It reads key/value pairs from key=value, JSON, CEF, LEEF and **XML** alike. XML is flattened
into dotted paths the way nested JSON keys are, in either common layout — an element per field
(`<src>10.1.1.5</src>`) or named data elements (`<Data Name="IpAddress">…</Data>`, the Windows
layout) — with attributes as `element.attribute` (`backend/services/parsing/xmlpairs.py`). A
document with a DOCTYPE or entity declarations, or over 64 KB, is not parsed as XML at all: a log
event has no use for either, and they are how XML parsers are made to expand entities or fetch
files. It is archived as text like any other line. Windows Security events have their own pack
(`windows_security`), because the names alone do not say that a logon event's `IpAddress` is where
the logon came from.

Key names are split into words to find their meaning (`srcPort` → src port, `clientip` → client
ip). A glued word is split only when every piece is a known word: accepting any remainder once
read `device_ip` as d(estination) + evice + ip, and `sensor_ip` as a source address.

What it does not do matters as much. Two addresses with nothing saying which is the
source are **not** assigned; they are listed under `unassigned_ips`. A port with no address
is not half an endpoint. When there is no usable device time, the event says
`unmapped.time_source = "received"` instead of passing the arrival time off as the device's.

Every event it produces carries `unmapped.tracelog_parse`: the parser, `verified: false`,
the overall confidence, and for each field its value, confidence and reason, plus the fields
it saw but did not fill and the values it rejected. A SIEM rule can require `verified: true`
or a confidence threshold.

"Confidence" here is an evidence score, not a measured probability: each kind of evidence has a
fixed weight — for key names, a standard field name 0.95, a key that names the side and the kind
0.85, a time, severity, user or threat key 0.8, a weak action key 0.75 — and a field is filled at
0.7 or above. The dashboard labels it *evidence score* for that reason. What is measured is the result:
85 correct, 18 missed, 0 wrong on the unseen-format corpus, and the real-log comparison in
[`PUBLIC_SAMPLES.md`](PUBLIC_SAMPLES.md).

Known packs are checked the same way. If a pack claims a line but produces impossible
values, the device's format has drifted (a firmware update inserted a column, say). One odd
value (an object name where an address should be) is dropped and reported in
`vendor_fields.<field>_rejected`; two or more, or any in a positional format such as PAN-OS
CSV, and the pack's output is discarded and the line goes to the generic parser with
`tracelog_parse.pack_drift`.

## Layer 2: new formats are detected as formats

Every line the generic parser handles gets a format id: a hash of its structure, never its
values (`inference.fingerprint`).

| Structure | What decides the format |
|---|---|
| key=value, JSON, XML, CEF, LEEF | kind, delimiter, syslog app and key names |
| delimited (CSV, TSV) | delimiter, number of columns, app |
| free text | app and the tokens with values masked: `<IP>`, `<N>`, `<HOST>`, `<ACTION>`, `<PROTO>`, ... |

The format registry (`backend/services/parsing/formats.py`, tables `log_formats`,
`log_format_samples`, `log_format_aliases`) counts lines per format in the same transaction
that stores them, and keeps which devices send it, when it was first and last seen, and up
to 200 sample lines. Free-text formats that differ in exactly one word (a user name, a status
word) are merged, and that word becomes a wildcard `<*>`, as template miners such as Drain
do; words that say which side an address is on (`from`, `to`, `src`, `dst`, `port`, `user`)
never become wildcards. A format whose lines came from a drifted pack is marked
`drift_from = <pack>`.

Parser Studio's **New log formats** tab shows them: 1,000 lines from a new device are one
row with a line count, not 1,000 rows.

## Layer 3: learn a parser from many lines, test it, approve it

One line cannot say what its values mean; a few hundred lines of the same format can.
`backend/services/parser_generation/learner.py` splits a format's samples 70/30, profiles
every part of the line across the 70%, and proposes a field for each part:

- which parts vary and which never change;
- what a varying part always is: an IP, a port, a protocol, an action word, a time, a severity;
- the word before it (`from`, `to`, `port`, `src=`), or an arrow inside the token;
- how its values are distributed: a destination port has a few well-known values, a source
  port many high ones.

Each proposal has a confidence and a reason. A proposal that rests on position alone, such
as two addresses in a row with nothing saying which is the source, is marked **needs
review**. The proposal is then run on the held-out 30% with exactly the code that will run
in production, and compared with the generic parser: lines recognised, lines parsed with all
values valid, fields gained, and every value where the two disagree.

The approval gate (`workflow.approve`) refuses unless:

- a named person confirmed or changed every *needs review* field;
- at least 90% of held-out lines are recognised and parse cleanly;
- the learned parser never disagrees with a value the generic parser proved.

Once approved, the parser is live within five seconds with no restart (`learned.py` re-reads
approved parsers when they change). Its events carry `tracelog_parse.verified: true`, the
parser id and the approver's name. Variants of the format seen earlier (a different trailing
word, say) are claimed by the same parser. Editing an approved parser takes it offline until
it is approved again.

A learned parser is checked on every line like any other: in a positional format, two or
more impossible values mean the format has drifted, and the line goes to the generic parser
with `tracelog_parse.learned_drift` instead of being passed on misaligned.

## Layer 4: re-parse history, as chained revisions

Lines that arrived before the parser existed were archived byte-for-byte. **Re-parse past
lines** (or `POST /api/formats/parsers/<id>/reparse`) parses them again
(`backend/services/parser_generation/reparse.py`):

- the archived line and the original event's hashed record are not changed or deleted; the
  original stays in the integrity chain;
- each new parse is appended to the chain as a new event for the same raw line, with
  `unmapped.tracelog_revision = {supersedes, supersedes_sequence, revision, parser_id, parser,
  approved_by, reason}`;
- `event_revisions` records the link and the original row's `superseded_by` column (an index,
  not part of the hashed record) points to the revision, so the Log
  Explorer, analytics, exports and correlation show the current version
  (`GET /api/events?include_superseded=true` shows both);
- revisions go to the configured outputs like new events, so SIEMs receive the corrected
  fields along with the uid of the event they replace;
- running it again changes nothing.

Reconciliation and the audit report account for revisions: archived lines equal original
events, events equal hash-chain records, and every superseded event must point to a chained
revision that names it.

## Measured

`python scripts/evaluate_unseen_formats.py --learned` scores the generic parser on 13 formats
TRACELOG has no pack for (`tests/unseen_corpus.py`: Huawei USG, Meraki MX, MikroTik, Ubiquiti
USG, F5 ASM, Barracuda CloudGen, WatchGuard, AWS VPC flow logs, Squid, Sophos UTM, Zscaler NSS,
Juniper ScreenOS, and PAN-OS after a column was inserted):

| Generic parser | Correct | Missed | Wrong |
|---|---:|---:|---:|
| Before these changes | 31 | 52 | **21** |
| Now | 83 | 20 | **0** |

The 20 missed fields are the ones a single line cannot prove, such as which of two
addresses is the source. A learned parser fills them. On lines generated with realistic
variation (`tests/format_samples.py`), learned from 150 lines with the reviewer accepting the
proposals marked for review, and scored on 100 new lines:

| Format | Generic: correct / missed / wrong | Learned: correct / missed / wrong | Confirmed by the reviewer |
|---|---|---|---|
| WatchGuard Firebox | 400 / 500 / 0 | 900 / 0 / 0 | both addresses and both ports (position only) |
| AWS VPC flow log | 100 / 700 / 0 | 800 / 0 / 0 | addresses, ports, protocol number, start time |
| OpenSSH logins | 100 / 400 / 0 | 500 / 0 / 0 | the user after "for" |

## API

| Call | Does |
|---|---|
| `GET /api/formats?status=new` | formats no parser knows (`new`, `learned`, `ignored`) |
| `GET /api/formats/<format_id>` | a format with sample lines and how they are parsed now |
| `POST /api/formats/<format_id>/learn` | learn a parser from its samples; body `{vendor, product, name}` |
| `PUT /api/formats/parsers/<id>` | change fields `{roles: {slot: field or null}, confirmed: [slot], reviewer}`; re-tests |
| `POST /api/formats/parsers/<id>/approve` | `{approved_by, confirmed: [slot]}`; refused with the reasons while the gate is not met |
| `POST /api/formats/parsers/<id>/reject` | take it out of use |
| `POST /api/formats/parsers/<id>/reparse` | re-parse history as chained revisions |
| `POST /api/formats/<format_id>/ignore?undo=false` | hide a format from the new list |

## Limits

- Direction in positional formats comes from a person, not from the data: TRACELOG proposes
  the order and flags it, and cannot know it.
- A free-text format that varies in more than one word per line splits into several formats;
  learning one of them still covers the others when the part it reads is the same.
- A learned parser recognises lines by structure. Two different messages that share a
  structure exactly would be read the same way; the held-out test and the disagreement check
  are there to catch that before approval.
