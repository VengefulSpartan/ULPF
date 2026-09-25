# Analytics and machine learning

The problem statement asks for "AI/ML-ready analytics". In TRACELOG that means four things, each of
which runs and is tested (`tests/test_ml.py`):

1. **A data contract.** Every event the Parquet output writes is one flat, typed row with a fixed set
   of columns, a null wherever the device did not say something, and the way back to the raw line.
2. **Window features.** Per source address, per user and per device, what happened in each 5-minute
   window, computed from that window and earlier ones only.
3. **A baseline detector.** Each window is compared with the entity's own history, or its peers'
   when it has none. What is far above it is written back as an OCSF Detection Finding through the
   same writer as every log line: archived, hash-chained and delivered to the SIEMs.
4. **An evaluation.** Synthetic days with eight attacks injected at known times, run end to end:
   six caught, the two built to be missed missed, and one benign false flag per day
   ([ML_EVALUATION.md](ML_EVALUATION.md)).

It is not a trained model running in production, and nothing in it is a probability. A flag says
what was measured and what it was compared with, and lists the events it came from.

## 1. The data contract

Written by the `parquet` output (`type: parquet` in `config/tracelog.yaml`, either layout), served at
`GET /api/ml/contract`, and defined in one place: `backend/services/ml/rows.py`. The feature
export builds its windows from the same rows, so a model trained on the lake's files and a feature
computed inside TRACELOG read the same values.

The rules:

- **A null means the device did not say.** Nothing is filled in. A Cisco ASA deny carries no byte
  counts, so its `bytes_in` and `bytes_out` are null, not 0. A FortiGate deny that says `sentbyte=0`
  has 0.
- **The time says where it came from.** `time_source` is `received` when the line carried no time
  TRACELOG could read and the arrival time stands in for it. Filter those out of anything that
  depends on timing.
- **Every row says who read it.** `fields_verified` is false when the fields were inferred by the
  evidence-based parser rather than read by a parser that knows the format. Train on verified rows,
  or keep the column as a feature.
- **Every row leads back to its bytes.** `sequence_num`, `raw_id` and `raw_sha256` identify the
  archived line and its place in the hash chain; `GET /api/events/{event_uid}` returns the raw
  line, its hash, whether the hash still matches, and the chain record.
- **Every file has every column with the same type.** A batch in which no device reported bytes
  still has an `int64` bytes column (`rows.arrow_schema()`). A value that is not what its column
  holds (a port that is not a number) becomes null in that column; the whole event is still in
  `ocsf`.

| Column | Type | Meaning |
|---|---|---|
| `time` | int64 | event time, epoch milliseconds UTC |
| `event_time` | string | the same time as ISO 8601 |
| `time_source` | string | 'device' when the device gave the time, 'received' when it did not |
| `class_uid` | int32 | OCSF class: 4001 Network Activity, 3002 Authentication, 2004 Detection Finding, 0 Base |
| `class_name` | string | OCSF class name |
| `activity_id` | int32 | OCSF activity id within the class |
| `activity_name` | string | OCSF activity name |
| `severity_id` | int32 | OCSF severity id, 0-6 |
| `severity` | string | OCSF severity name |
| `status_id` | int32 | Authentication outcome: 1 success, 2 failure; null when the device gave none |
| `action_id` | int32 | OCSF action id: 1 allowed, 2 denied; null when the device gave none |
| `action` | string | OCSF action name |
| `disposition_id` | int32 | OCSF disposition id (1 allowed, 2 blocked, 6 dropped, 19 alert) |
| `disposition` | string | OCSF disposition name |
| `src_ip` | string | source address |
| `src_port` | int32 | source port |
| `src_hostname` | string | source name, when the device logged a name instead of an address |
| `dst_ip` | string | destination address |
| `dst_port` | int32 | destination port |
| `dst_hostname` | string | destination name, when the device logged a name instead of an address |
| `protocol` | string | transport protocol name, lower case |
| `protocol_num` | int32 | IANA protocol number |
| `direction_id` | int32 | OCSF direction: 0 unknown, 1 inbound, 2 outbound, 3 lateral |
| `bytes_in` | int64 | bytes from destination to source, as the device reported |
| `bytes_out` | int64 | bytes from source to destination, as the device reported |
| `packets` | int64 | packets, as the device reported |
| `user_name` | string | user name |
| `finding_title` | string | Detection Finding title (signature, rule name) |
| `finding_uid` | string | Detection Finding id (signature or rule id) |
| `vendor` | string | device vendor |
| `product` | string | device product |
| `device_hostname` | string | the device that logged the event, by the hostname in its log |
| `sender_ip` | string | the address the line arrived from (the device, or a relay) |
| `parser` | string | what read the line: a vendor pack's name, 'learned', 'generic_cef' / 'generic_leef', or 'generic_inferred' |
| `fields_verified` | bool | true when a parser that knows the format read the fields (vendor pack, approved learned parser, CEF/LEEF); false when they were inferred from evidence |
| `sequence_num` | int64 | position in the event hash chain |
| `event_uid` | string | TRACELOG event id |
| `raw_id` | string | id of the archived raw line |
| `raw_sha256` | string | SHA-256 of the bytes received |
| `ocsf` | string | the whole OCSF event as JSON |

Querying the lake directly, with DuckDB for example (times are UTC):

```sql
SET TimeZone = 'UTC';
SELECT src_ip,
       time_bucket(INTERVAL 5 MINUTE, to_timestamp(time / 1000)) AS window_start,
       count(*) AS events,
       count(DISTINCT dst_port) AS distinct_dst_ports,
       sum(bytes_out) AS bytes_out
FROM read_parquet('data/lake/**/*.parquet', hive_partitioning = false)
WHERE fields_verified AND class_uid = 4001
GROUP BY ALL
ORDER BY distinct_dst_ports DESC
LIMIT 5;
```

On the first synthetic day below this puts the port sweep (`203.0.113.66`, 80 ports at 13:05) on
top. `hive_partitioning = false` because the default layout's directories repeat `class_uid`, which
is also a column.

## 2. Window features

`backend/services/ml/features.py`. One row per entity and window in which the entity appears.

| Entity | Rows are about | Taken from |
|---|---|---|
| `src_ip` | one source address | `src_ip` |
| `user` | one user name | `user_name` |
| `device` | one device | `device_hostname`, or `sender_ip` when the log names no host |

| Feature | What it counts in the window |
|---|---|
| `events` | events |
| `denied` | events denied, blocked or dropped (`action_id` 2 or `disposition_id` 2 or 6) |
| `deny_ratio` | `denied / events` |
| `distinct_dst_ips`, `distinct_dst_ports`, `distinct_src_ips` | distinct values |
| `new_dst_ips`, `new_dst_share` | destinations the entity had not reached in any earlier window, as a count and a share |
| `bytes_out`, `bytes_in` | sums of what the device reported; null when no event in the window reported them |
| `auth_failures`, `auth_successes` | Authentication events with `status_id` 2 or 1 |
| `findings` | Detection Findings from devices (TRACELOG's own are left out) |
| `max_severity_id` | the highest severity |
| `unverified_events`, `received_time_events` | how many of the window's events had inferred fields or no device time |
| `hour_of_day`, `day_of_week` | of the window's start, UTC |
| `history_windows` | how many earlier windows the entity appears in, within what was read |
| `first_sequence`, `last_sequence` | the chain positions of the window's first and last event |

**No row sees the future.** A row is computed from the events in its window, and "new destination"
from earlier windows. Adding or removing later events does not change it
(`test_a_window_is_computed_from_its_own_and_earlier_events_only`). So the export can be split by
time into training and test sets without leakage, and a window scored live, as it closes, gets the
same values as the same window computed from the archive a month later.

Getting them:

```bash
python scripts/export_features.py                          # last 24 h from the database, all three entities
python scripts/export_features.py --hours 168 -o week.csv
python scripts/export_features.py --parquet data/lake      # from the Parquet output's files
curl -o src.csv 'http://127.0.0.1:8000/api/ml/features?entity_type=src_ip&hours=24'
```

The Python path reads events through the OCSF view at about 9,000 events a second (32,142 events in
3.7 s on the 2-vCPU sandbox, `docs/ML_EVALUATION.md`), which suits hours to days of a site's logs.
For months of data, compute the same windows over the Parquet files with DuckDB or Spark, as in the
query above.

## 3. The baseline detector

`backend/services/ml/baseline.py`. For each scored feature, a window's value is compared with a
history of the same feature:

- **its own history**: the entity's earlier windows in the last 24 hours, when there are at least 8;
- **its peers**: otherwise, every entity of the same kind in the 24 hours before the window, when
  there are at least 30 of those windows. An address seen for the first time is compared with every
  source address;
- **neither**: the window is not scored, and is counted as not scored.

The spread is the median absolute deviation scaled to a standard deviation (1.4826 × MAD), or 1.2533
× the mean absolute deviation when the MAD is 0 (Iglewicz and Hoaglin, 1993). A feature is flagged
when its robust z, (value − median) / spread, is at least 3.5, their cut-off for outliers, **and**
the value is at least a minimum above the median, so that 1 failed login where there are usually 0
is not an alert. Only increases are flagged.

| Entity | Feature | Minimum increase over the median |
|---|---|---|
| `src_ip` | `events` | 100 |
| | `denied` | 20 |
| | `distinct_dst_ips` | 20 |
| | `distinct_dst_ports` | 15 |
| | `bytes_out` | 50 MB |
| | `auth_failures` | 5 |
| | `findings` | 5 |
| `user` | `auth_failures` | 5 |
| | `distinct_src_ips` | 5 |
| `device` | `events` | 1,000 |
| | `denied` | 100 |
| | `findings` | 20 |

These values, the threshold, the lookback and the history minimums were fixed before the
evaluation was first run. Every flag has the same severity, Medium: an anomaly is a reason to look,
not a verdict.

### What a flag is

One JSON line per flagged entity and window, all its reasons in it. This is the port sweep from the
evaluation (evidence list shortened):

```json
{
  "tracelog_detector": "baseline", "version": 1,
  "finding_uid": "baseline-545e5ed9efc5a40d",
  "title": "Unusual number of destination ports and denied connections from 203.0.113.66",
  "summary": "80 denied connections in 5 min; all peers' 5473 earlier windows: median 0, highest 4; 80 destination ports in 5 min; all peers' 5473 earlier windows: median 2, highest 7, robust z 52.6",
  "entity_type": "src_ip", "entity": "203.0.113.66",
  "window_start": "2026-09-21T13:05:00Z", "window_end": "2026-09-21T13:10:00Z", "time": "2026-09-21T13:10:00Z",
  "severity": "medium", "threshold": 3.5,
  "reasons": [
    {"feature": "denied", "value": 80.0, "baseline": "peers", "history": 5473, "median": 0.0, "highest": 4.0,
     "spread": 0.619, "spread_from": "mean absolute deviation", "robust_z": 129.341, "min_excess": 20},
    {"feature": "distinct_dst_ports", "value": 80.0, "baseline": "peers", "history": 5473, "median": 2.0,
     "highest": 7.0, "spread": 1.483, "spread_from": "mad", "robust_z": 52.61, "min_excess": 15}
  ],
  "evidence": {"events": 80, "first_sequence": 25003, "last_sequence": 25097,
               "event_uids": ["ec921f35-f3c7-40fd-ad51-04233c79c8f2", "4cbb45a2-a920-4920-bc77-61eb80d5f86b", "..."]}
}
```

The summary prints a robust z only when it comes from the MAD. When more than half of the history
is one value (0 denied connections, usually), the fallback spread is tiny and its z is a large
number that says less than "median 0, highest 4" does. The z is still in `reasons`.

### Where it goes

The line is written through `StreamIngestor`, the writer every log line takes, with transport
`internal` and input `baseline-detector`. The `tracelog_baseline` pack (`backend/services/vendors/
tracelog.py`) reads it into an OCSF Detection Finding (class 2004): `finding_info.title` and `uid`,
`src_endpoint.ip` or `user.name` for the entity, `message` the summary, and the reasons and
evidence under `unmapped.vendor_fields`. So a flag is:

- **archived and chained** like any line: its raw bytes kept, their SHA-256 stored, linked into the
  event hash chain;
- **delivered** to every configured output, where a SIEM sees it next to the device alerts;
- **traceable**: its evidence lists up to 50 of the events it was computed from, in chain order,
  with their count and chain positions. Each resolves to an archived line whose hash matches
  (`evidence_ok` in the evaluation: 876 of 876);
- **written once**: its id comes from the entity and the window, and a run finds the ids already
  stored and skips them, so running the detector again over the same period writes nothing;
- **not fed back**: the features leave TRACELOG's own findings out, so the detector never learns
  from its output.

A line that imitates the format but arrives over syslog or HTTP is read the same way; its
`transport` and `sender_ip` show where it came from. Restricting who may send is part of the
security work the audit lists.

### Running it

```bash
python scripts/run_baseline.py                      # score the last hour's complete windows, write findings
python scripts/run_baseline.py --hours 24 --dry-run # show what it would flag
curl -X POST 'http://127.0.0.1:8000/api/ml/baseline/run?hours=1'
BASELINE_EVERY_MINUTES=5 python run_app.py          # inside the API server, 30 s after each window closes
```

The scheduled run scores the last two intervals each time, so a window whose events arrived late
is scored again; a flag already written is not written twice. Scoring one hour against 24 hours of
history reads every event of those 25 hours, which is the cost that grows with volume.

## 4. Results on synthetic days

[ML_EVALUATION.md](ML_EVALUATION.md), regenerated by `python scripts/evaluate_baseline.py`. Three
seeds of a synthetic day: 30 internal hosts, internet scan noise, 25 VPN users, and a nightly
backup, all as FortiGate syslog lines through the real pipeline.

| Attack | Caught (3 seeds) | Flagged by |
|---|---|---|
| Fast port sweep, 80 ports in 90 s | 3/3 | destination ports and denies, against peers |
| VPN brute force, 40 failures as `admin` | 3/3 | failed logins, for the address and for the user |
| Password spray, 1 failure for each of 20 users | 3/3 | failed logins for the address |
| Exfiltration, ~800 MB in 10 min | 3/3 | bytes sent, against the host's own history |
| Lateral SMB scan, 60 hosts in 3 min | 3/3 | destinations and denies, against its own history |
| Distributed scan, 300 addresses × 1 probe | 3/3 | denies at the device |
| Slow port scan, 2–3 ports per window for 2 h | 0/3, as designed | — |
| Slow exfiltration, ~20 MB per window for 2 h | 0/3, as designed | — |

Each caught attack was flagged in the window it started in, 2 to 4 minutes after its first line.
One false flag per day: the nightly 300 MB backup, which 24 hours of history has never seen. That is
0.11 per 1,000 entity-windows scored. The findings were all valid OCSF, the chain verified, a second
run wrote nothing, and replaying seven hours one at a time gave exactly the flags of one pass.

**What this does not show.** The benign traffic comes from steady random processes; real traffic
is burstier, so real false-flag rates will be higher, by an amount nobody knows until the detector
runs on a real network. The attacks are clean and the network is small.

## 5. Training a model on the export

The export is meant for this. scikit-learn is not a TRACELOG dependency; this was run with 1.9.1 on
the features of the first seed (`python scripts/export_features.py --db <evaluation db> --entity
src_ip --hours 24000 -o features.csv`):

```python
import pandas as pd
from sklearn.ensemble import IsolationForest

f = pd.read_csv("features.csv")
cols = ["events", "denied", "distinct_dst_ips", "distinct_dst_ports", "bytes_out", "auth_failures", "findings"]
f["bytes_out"] = f["bytes_out"].fillna(0)        # the model needs a number; null meant "not reported"
train = f[f.window_start < "2026-09-21T12:00:00Z"]           # the first 12 hours
test = f[f.window_start >= "2026-09-21T12:00:00Z"].copy()    # the rest: no row of it saw the future
model = IsolationForest(random_state=0).fit(train[cols])
test["anomaly"] = -model.score_samples(test[cols])            # higher = more unusual
test["rank"] = test["anomaly"].rank(ascending=False, method="min").astype(int)
print(test.nsmallest(12, "rank")[["rank", "window_start", "entity"] + cols].to_string(index=False))
```

Of 4,248 test windows it ranks the lateral scan first, then nine windows tied second: internet
scanners that sent three probes and tripped one IPS signature. The other attacks come 16th (brute
force), 17th (exfiltration), 18th (port sweep) and 31st (password spray); the backup is 20th. An
unsupervised model finds what is rare, and in perimeter logs a scanner that trips a signature is
rare. It has no idea which rarity matters, and no way to say why it ranked a window where it did.
That is why the detector TRACELOG ships is the baseline, whose every flag can be checked by reading
it, and why the features are exported: a team with labelled incidents can train something better
on them, split by time, with the lineage columns to trace what it flags.

## 6. Limits

- **Per-window only.** An attack spread thin over hours stays under every window's minimum, as the
  slow scan and slow exfiltration show. Longer windows or an accumulating detector would see them.
- **24 hours of memory, no daily rhythm.** A daily or weekly job looks new. A per-hour-of-day
  baseline or a longer lookback would learn it; neither is built.
- **Peers are everyone of the same kind.** Internal hosts and internet addresses share one peer
  group; grouping by subnet or role would give newcomers a fairer comparison.
- **Only increases.** A device that goes quiet is not flagged.
- **Not run on real traffic.** The public sample logs ([PUBLIC_SAMPLES.md](PUBLIC_SAMPLES.md)) are
  a few hundred lines per source from unrelated networks, not a continuous stream from one network,
  so there is nothing to baseline in them.
