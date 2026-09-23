# 1. Emit OCSF 1.1.0, and cap what we emit at 1.3

Status: accepted, 24 September 2026.

## Context

OCSF has released well past 1.1 — 1.9.0 is current at the time of writing. TRACELOG stamps every
event `metadata.version = 1.1.0` and validates against the required attributes of the four classes
it emits: Network Activity (4001), Authentication (3002), Detection Finding (2004) and Base Event
(0) for anything it will not classify.

Three things bear on the choice of version:

- **Amazon Security Lake reads OCSF 1.3 and earlier** for custom sources. Anything newer is written
  into the bucket and not read. That is the strictest consumer we target, and it sets a ceiling.
- **SIEMs are not strict.** Splunk, Elastic, Sentinel, QRadar, Wazuh, Loki and the rest ingest our
  JSON and map fields themselves; none of them refuse an event for being 1.1 rather than 1.9.
- **The attributes we depend on did not move between 1.1 and 1.3.** The base event requirements
  (`class_uid`, `category_uid`, `activity_id`, `severity_id`, `time`, `type_uid`, `metadata`), the
  `finding_info` requirement on Detection Finding, `connection_info.direction_id`, and the
  security-control action and disposition enums are the same across that range. Detection Finding
  2004 already replaces Security Finding 2001, which OCSF deprecated in 1.1.

Chasing the newest version would mean re-checking every class against a schema whose additions we
do not use, for no consumer that asks for it — and it would break the one consumer with a hard
requirement.

## Decision

Emit **1.1.0** by default. Make the version a setting, `OCSF_VERSION`, accepting **1.1.0, 1.2.0 or
1.3.0** — the versions whose rules we have actually checked our events against, not the versions
OCSF has published. Anything else is refused at startup with a message that points here.

The Security Lake output enforces the ceiling independently: a batch whose events carry a version
above 1.3 is a non-retryable delivery error, so those events dead-letter instead of filling a bucket
the lake will silently ignore.

## Consequences

**What this buys.** Every target consumes what we emit, including the strictest one. The validator
is a single function (`backend/services/normalization/ocsf_export.validate`) with one set of rules
rather than a matrix. The dashboard's OCSF-conformance figure means one thing.

**What it costs.** Classes and attributes introduced after 1.3 are unavailable to us — if we later
want a class that only exists in a newer schema, the version has to move first. A reviewer who
expects "latest" will ask why, which is what this record is for.

**Where the version lives.** `backend/config.py` holds the setting; `ocsf_export.OCSF_VERSION` reads
it and is the only place the string appears. The normaliser stamps `metadata.version` from it, and
`to_ocsf` writes it into every exported event.

## Moving to a newer version

The work is contained, and in this order:

1. Change `OCSF_VERSION` and add the target to `SUPPORTED_OCSF_VERSIONS` in `backend/config.py`.
2. Re-check the required attributes of the four classes against that schema release and update
   `REQUIRED_BY_CLASS` and `validate()` in `ocsf_export.py` where they differ.
3. Re-check the enums that carry ids — action, disposition, status, direction, observable types.
4. Run `pytest -q`; `tests/test_ocsf_version.py` fails loudly if events stop validating.
5. If the target is above 1.3, decide what the Security Lake output should do: it refuses by design.

## Revisit this when

Security Lake raises its ceiling; a SIEM we target requires a newer schema; or we add an event class
that does not exist in 1.1–1.3 — DNS Activity and HTTP Activity, the two most likely additions, both
exist in 1.1 and do not force a move.

## References

- OCSF schema releases: <https://github.com/ocsf/ocsf-schema/releases>
- Amazon Security Lake, custom source requirements:
  <https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html>
- `backend/services/normalization/ocsf_export.py` — the export and the validator
- `tests/test_ocsf_version.py` — the version is stamped everywhere, and 1.2/1.3 still validate
