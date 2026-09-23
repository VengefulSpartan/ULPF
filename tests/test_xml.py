"""
XML, which PS 26156 names among the formats a universal framework has to take.

Three things are held here. XML device logs are read by the same evidence rules as JSON, whichever
of the two common layouts they use. Windows Security events — the XML a SOC sees most — are read by a
pack that knows what their fields mean, because the names alone do not say which side of a logon an
address is on. And XML that could be used against the parser (entity declarations, a DOCTYPE,
oversized documents) is not parsed as XML at all; it is archived as text like any other line.

The word-splitter tests at the end guard a wrong-field bug found while adding XML: "device" was being
split into "d" + "evice", and "d" means destination.
"""
import pytest

from backend.services.normalization.ocsf_export import to_ocsf, validate
from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
from backend.services.parsing.dispatch import parse_log
from backend.services.parsing.inference import fingerprint, key_role, structure
from backend.services.parsing.xmlpairs import MAX_BYTES, xml_pairs
from backend.services.vendors.envelope import split_envelope

ELEMENTS = ("<log><time>2026-09-21T10:15:02Z</time><src_ip>10.1.1.5</src_ip><dst_ip>203.0.113.9</dst_ip>"
            "<dst_port>443</dst_port><proto>tcp</proto><action>deny</action></log>")
ATTRIBUTES = ('<event time="2026-09-21T10:15:02Z" action="deny" protocol="tcp">'
              '<source ip="10.1.1.5" port="51514"/><destination ip="203.0.113.9" port="443"/></event>')
IN_SYSLOG = ("<134>Sep 21 10:15:02 fw9 xmlfw: <traffic><src>10.1.1.5</src><dst>203.0.113.9</dst>"
             "<dport>443</dport><action>allow</action></traffic>")

WINDOWS = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
           '<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>'
           '<EventID>{id}</EventID><TimeCreated SystemTime="2026-09-21T10:15:02.1234567Z"/>'
           '<Computer>DC01.corp.local</Computer></System><EventData>'
           '<Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">CORP</Data>'
           '<Data Name="LogonType">3</Data><Data Name="IpAddress">{ip}</Data><Data Name="IpPort">{port}</Data>'
           '{extra}</EventData></Event>')


def windows(event_id, ip="203.0.113.7", port="51514", extra=""):
    return WINDOWS.replace("{id}", event_id).replace("{ip}", ip).replace("{port}", port).replace("{extra}", extra)


def normalised(line):
    fmt, parsed = parse_log(line)
    return fmt, parsed, OCSFNormalizer.normalize(parsed, line, "raw-1", "hash-1")


@pytest.mark.parametrize("line", [ELEMENTS, ATTRIBUTES, IN_SYSLOG])
def test_device_xml_is_read_like_json_in_either_layout(line):
    fmt, parsed, ev = normalised(line)
    assert fmt == "generic_inferred" and parsed["tracelog_parse"]["structure"]["kind"] == "xml"
    assert ev.class_uid == 4001
    assert ev.src_endpoint.ip == "10.1.1.5" and ev.dst_endpoint.ip == "203.0.113.9" and ev.dst_endpoint.port == 443
    assert ev.action in ("deny", "allow")


def test_attribute_layout_keeps_ports_on_their_own_side():
    _, _, ev = normalised(ATTRIBUTES)
    assert ev.src_endpoint.port == 51514 and ev.dst_endpoint.port == 443 and ev.time.startswith("2026-09-21T10:15:02")


def test_xml_lines_of_one_format_share_a_format_id_whatever_their_values():
    other = ELEMENTS.replace("10.1.1.5", "10.9.9.9").replace("443", "22").replace("deny", "allow")
    ids = {fingerprint(structure(line), split_envelope(line))["format_id"] for line in (ELEMENTS, other)}
    assert len(ids) == 1
    assert fingerprint(structure(ATTRIBUTES), split_envelope(ATTRIBUTES))["format_id"] not in ids


@pytest.mark.parametrize("line", [
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><log><src>&xxe;</src></log>',
    "<log><src>10.1.1.5</src><dst>unclosed",
])
def test_xml_that_could_be_used_against_the_parser_is_left_as_text(line):
    assert xml_pairs(line) is None
    fmt, parsed = parse_log(line)
    assert parsed["tracelog_parse"]["structure"]["kind"] != "xml"
    assert "root:" not in str(parsed)                   # nothing was fetched or expanded


def test_an_oversized_document_is_not_parsed():
    huge = "<log>" + "<f>x</f>" * (MAX_BYTES // 8) + "</log>"
    assert len(huge) > MAX_BYTES and xml_pairs(huge) is None


def test_windows_failed_logon_names_the_address_it_came_from():
    fmt, parsed, ev = normalised(windows("4625", extra='<Data Name="FailureReason">%%2313</Data>'))
    assert fmt == "windows_security"
    assert ev.class_uid == 3002 and ev.activity_name == "Logon" and ev.status == "failure"
    assert ev.user.name == "alice"
    assert (ev.src_endpoint.ip, ev.src_endpoint.port) == ("203.0.113.7", 51514)
    assert ev.dst_endpoint is None or ev.dst_endpoint.ip is None   # the address is the source, never guessed as destination
    assert ev.time.startswith("2026-09-21T10:15:02.123")          # seven fractional digits read
    assert parsed["device_hostname"] == "DC01.corp.local"
    assert parsed["vendor_fields"]["FailureReason"] == "%%2313"


def test_windows_successful_logon_logoff_and_ntlm():
    _, _, ok = normalised(windows("4624", ip="::ffff:10.0.0.8", port="0"))
    assert ok.status == "success" and ok.src_endpoint.ip == "10.0.0.8" and ok.src_endpoint.port is None
    _, _, off = normalised(windows("4634", ip="-", port="-"))
    assert off.activity_name == "Logoff" and off.src_endpoint.ip is None
    _, _, ntlm = normalised(windows("4776", ip="-", port="-", extra='<Data Name="Status">0xc000006a</Data>'))
    assert ntlm.status == "failure"


def test_other_windows_events_are_kept_not_guessed_into_a_class():
    fmt, parsed, ev = normalised(windows("4688", ip="-", port="-"))
    assert fmt == "windows_security" and ev.class_uid == 0
    assert parsed["vendor_fields"]["EventID"] == "4688"


@pytest.mark.parametrize("line", [ELEMENTS, ATTRIBUTES, IN_SYSLOG, windows("4625"), windows("4624"),
                                  windows("4688", ip="-", port="-")])
def test_every_xml_event_exports_as_valid_ocsf(line):
    _, _, ev = normalised(line)
    assert validate(to_ocsf(ev.model_dump())) == []
