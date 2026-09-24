"""
The real-log scorer (scripts/evaluate_public_samples.py) is only as honest as its comparison and
its explanations. These tests run offline on hand-made records: a list-valued answer matches any
element, a disagreement is explained only when the corpus holds the evidence, and anything else
stays unexplained.
"""
from collections import Counter, defaultdict

from scripts.evaluate_public_samples import _same, explain, message_key


def test_list_valued_answers_match_any_element():
    assert _same("src_ip", "10.0.0.1", ["192.0.2.1", "10.0.0.1"])
    assert not _same("src_ip", "10.0.0.2", ["192.0.2.1", "10.0.0.1"])
    assert _same("dst_port", 443, "443")


def test_cisco_message_key_names_id_and_direction():
    assert message_key("%ASA-6-302013: Built outbound TCP connection 1 for a:b/1 to c:d/2") == "302013 outbound"
    assert message_key("%FTD-6-302016: Teardown UDP connection 1 for a:b/1 to c:d/2") == "302016"
    assert message_key("date=2026-09-21 srcip=10.0.0.1") is None


def _counts(**packages):
    table = defaultdict(lambda: defaultdict(Counter))
    for package, (agree, wrong) in packages.items():
        table["302013 outbound"][package].update(agree=agree, wrong=wrong)
    return table


def _disagreement(**overrides):
    d = {"source": "cisco_ftd", "field": "src_ip", "reversed": True, "direction_source": None,
         "message": "302013 outbound", "our_source": "10.0.0.1", "elastic_built_source": None}
    d.update(overrides)
    return d


def test_key_conflict_needs_another_package_that_agrees_without_exception():
    cause, evidence = explain(_disagreement(), _counts(cisco_asa=(88, 0), cisco_ftd=(0, 88)))
    assert cause == "key_conflict" and "cisco_asa" in evidence
    # one exception in the other package and the explanation no longer holds
    assert explain(_disagreement(), _counts(cisco_asa=(88, 1), cisco_ftd=(0, 88)))[0] == "other"
    # a value disagreement (not the two ends swapped) is never explained this way
    assert explain(_disagreement(reversed=False), _counts(cisco_asa=(88, 0), cisco_ftd=(0, 88)))[0] == "other"


def test_teardown_direction_is_checked_against_elastics_own_built_event():
    d = _disagreement(source="cisco_asa", message="302016", direction_source="built message",
                      elastic_built_source="10.0.0.1")
    assert explain(d, _counts()) == ("built_message", "elastic_built_agrees")
    d["elastic_built_source"] = "192.0.2.53"
    assert explain(d, _counts()) == ("built_message", "elastic_built_reversed")


def test_nothing_else_is_explained():
    d = _disagreement(source="stormshield", message=None)
    assert explain(d, _counts()) == ("other", "")
