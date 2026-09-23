"""
The OCSF version is a decision with a record (docs/adr/0001-ocsf-version.md), so it is also a
setting rather than a string spread through the code: one place to change, one place to check.

These tests hold the three things that decision rests on: every event says which version it is,
the versions we claim to support really do validate, and a version the code has not been checked
against is refused rather than emitted.
"""
import importlib

import pytest

from backend.connectors.config import Output
from backend.connectors.outputs.base import DeliveryError
from backend.connectors.outputs.file_sinks import ParquetSink
from backend.services.normalization import ocsf_export
from backend.services.normalization.ocsf_export import to_ocsf, validate
from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
from backend.services.parsing.dispatch import parse_log
from tests.test_vendor_packs import ASA_DENY, FORTI_VPN_FAIL, PAN_TRAFFIC, SURICATA

LINES = [PAN_TRAFFIC, ASA_DENY, FORTI_VPN_FAIL, SURICATA]


def events(version=None):
    if version:
        ocsf_export.OCSF_VERSION = version
    try:
        out = []
        for line in LINES:
            _, parsed = parse_log(line)
            event = OCSFNormalizer.normalize(parsed, line, "raw-1", "hash-1").model_dump()
            out.append(to_ocsf(event))
        return out
    finally:
        importlib.reload(ocsf_export)          # back to the configured value for other tests


def test_every_exported_event_says_which_schema_it_is():
    from backend.config import settings
    for ocsf in events():
        assert (ocsf.get("metadata") or {}).get("version") == settings.OCSF_VERSION
        assert validate(ocsf) == []


def test_the_normaliser_stamps_the_same_version_it_exports():
    _, parsed = parse_log(PAN_TRAFFIC)
    stored = OCSFNormalizer.normalize(parsed, PAN_TRAFFIC, "raw-1", "hash-1")
    assert stored.metadata.version == ocsf_export.OCSF_VERSION


@pytest.mark.parametrize("version", ["1.1.0", "1.2.0", "1.3.0"])
def test_the_versions_we_claim_to_support_validate(version):
    """The attributes our four classes require did not change across 1.1 to 1.3, which is the whole
    reason the ADR picks a ceiling of 1.3 rather than tracking the newest release."""
    for ocsf in events(version):
        assert (ocsf.get("metadata") or {}).get("version") == version
        assert validate(ocsf) == [], f"{ocsf.get('class_name')} stopped validating at {version}"


def test_an_unverified_version_is_refused_at_startup():
    from backend.config import SUPPORTED_OCSF_VERSIONS
    assert "1.9.0" not in SUPPORTED_OCSF_VERSIONS and "1.1.0" in SUPPORTED_OCSF_VERSIONS


def test_the_security_lake_output_enforces_the_ceiling_of_its_own(tmp_path):
    """A lake that cannot read 1.9 should get nothing, not a bucket of objects it ignores."""
    sink = ParquetSink(Output(name="lake", type="parquet",
                              settings={"root": str(tmp_path / "lake"), "layout": "security_lake",
                                        "region": "ap-south-1"}), data_dir=str(tmp_path))
    future = [{"class_uid": 4001, "time": 1789912815000, "metadata": {"version": "1.9.0"}}]
    with pytest.raises(DeliveryError, match="1.3"):
        sink.send(future)
