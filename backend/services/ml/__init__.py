"""
What TRACELOG hands to analytics and machine learning (docs/ML_DATA.md):

- rows.py      the data contract: one flat, typed row per OCSF event, with where each value came from;
- features.py  per-entity 5-minute windows computed from those rows, each window from its own events
               and earlier ones only;
- baseline.py  a statistical baseline that flags windows far above an entity's own history (or its
               peers') and writes each flag back as an OCSF Detection Finding through the one writer,
               so a flag is archived, hash-chained and delivered like any device's alert.
"""
