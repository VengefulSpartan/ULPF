"""
The generic parser finds what a field means from its name, split into words: srcPort is src + port,
clientip is client + ip. Glued words are split against a vocabulary of known words, and a split
used to be accepted whatever the last piece was. So "device" became d + evice, and d means
destination: device_ip was read as a destination address, sensor_ip and system_ip as source
addresses. Those are wrong fields, the one failure this parser exists to avoid.
"""
import pytest

from backend.services.parsing.inference import key_role


@pytest.mark.parametrize("key", ["device_ip", "deviceIp", "sensor_ip", "system_ip", "data_port",
                                 "EventData.IpAddress", "EventData.IpPort"])
def test_ordinary_words_are_not_read_as_source_or_destination(key):
    assert key_role(key)[0] is None


@pytest.mark.parametrize("key, role", [("srcport", "src_port"), ("dport", "dst_port"), ("sport", "src_port"),
                                       ("clientip", "src_ip"), ("serverport", "dst_port"), ("dstip", "dst_ip"),
                                       ("sip", "src_ip"), ("dip", "dst_ip")])
def test_glued_field_names_are_still_read(key, role):
    assert key_role(key)[0] == role
