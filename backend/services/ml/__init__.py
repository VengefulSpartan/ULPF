"""
What TRACELOG hands to analytics and machine learning (docs/ML_DATA.md):

- rows.py      the data contract: one flat, typed row per OCSF event, with where each value came from;
- features.py  per-entity 5-minute windows computed from those rows, each window from its own events
               and earlier ones only;
- baseline.py  a statistical baseline that flags windows far above an entity's own history (or its
               peers') and writes each flag back as an OCSF Detection Finding through the one writer,
               so a flag is archived, hash-chained and delivered like any device's alert.
"""
import os

BLAS_THREAD_VARIABLES = ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")


def limit_blas_threads() -> None:
    """One BLAS thread per process, unless the environment already says otherwise.

    numpy's OpenBLAS starts a thread per logical CPU when it is first imported and sets aside
    memory for each. The analytics here are group-bys and medians, with no linear algebra, so those
    threads buy nothing. On Windows the memory is committed up front, and on a machine with many
    cores the import can fail with "OpenBLAS error: Memory allocation still failed". It has to run
    before numpy is imported, so the entry points call it first.
    """
    for name in BLAS_THREAD_VARIABLES:
        os.environ.setdefault(name, "1")


limit_blas_threads()      # importing this package is enough, before features.py or baseline.py load numpy
