import pytest
from backend.services.parser_generation.generator import ParserGenerator
from backend.services.parser_generation.tester import ParserTester

def test_generate_candidate_parser_cef():
    samples = [
        'CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|traffic-start|3|src=192.168.1.10 dst=10.0.0.5 spt=54321 dpt=443 proto=TCP act=allow',
        'CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|traffic-end|3|src=192.168.1.20 dst=10.0.0.8 spt=54322 dpt=80 proto=TCP act=deny'
    ]
    candidate = ParserGenerator.generate_candidate(
        sample_logs=samples,
        name="PAN-OS Auto Parser",
        vendor="Palo Alto Networks",
        product="PAN-OS"
    )

    assert candidate.status == "candidate"
    assert candidate.tested is False
    assert candidate.rule.format_type == "cef"
    assert len(candidate.rule.mappings) >= 5

def test_test_candidate_parser_passes():
    samples = [
        'CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|traffic-start|3|src=192.168.1.10 dst=10.0.0.5 spt=54321 dpt=443 proto=TCP act=allow',
        'CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|traffic-end|3|src=192.168.1.20 dst=10.0.0.8 spt=54322 dpt=80 proto=TCP act=deny'
    ]
    candidate = ParserGenerator.generate_candidate(
        sample_logs=samples,
        name="PAN-OS Auto Parser",
        vendor="Palo Alto Networks",
        product="PAN-OS"
    )

    tested = ParserTester.test_candidate(candidate, samples)
    assert tested.tested is True
    assert tested.validation is not None
    assert tested.validation.total_samples == 2
    assert tested.validation.passed_samples == 2
    assert tested.validation.accuracy_score == 100.0
    assert len(tested.validation.sample_results) == 2

def test_test_candidate_with_malformed_sample():
    samples = [
        'CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|traffic-start|3|src=192.168.1.10 dst=10.0.0.5 spt=54321 dpt=443 proto=TCP act=allow',
        'THIS IS COMPLETELY CORRUPTED GARBAGE LOG LINE'
    ]
    candidate = ParserGenerator.generate_candidate(
        sample_logs=samples[:1],
        name="PAN-OS Parser",
        vendor="Palo Alto",
        product="PAN-OS"
    )

    tested = ParserTester.test_candidate(candidate, samples)
    assert tested.tested is True
    assert tested.validation.passed_samples == 1
    assert tested.validation.failed_samples == 1
    assert tested.validation.accuracy_score == 50.0
    assert tested.validation.sample_results[1].passed is False
