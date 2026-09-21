import os
import pytest
from typing import List, Tuple
from core.detector.detector import FormatDetector

# Paths to sample files
SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples"))

SAMPLE_FILES = {
    "cef": os.path.join(SAMPLES_DIR, "cef.log"),
    "leef": os.path.join(SAMPLES_DIR, "leef.log"),
    "json": os.path.join(SAMPLES_DIR, "json.log"),
    "xml": os.path.join(SAMPLES_DIR, "xml.log"),
    "kv": os.path.join(SAMPLES_DIR, "kv.log"),
    "csv": os.path.join(SAMPLES_DIR, "csv.log"),
    "syslog_rfc5424": os.path.join(SAMPLES_DIR, "syslog_rfc5424.log"),
    "syslog_rfc3164": os.path.join(SAMPLES_DIR, "syslog_rfc3164.log"),
    "unknown": os.path.join(SAMPLES_DIR, "unknown.log"),
}


def load_sample_lines() -> List[Tuple[str, int, str, str]]:
    """Load sample lines from files.
    Returns list of tuples: (expected_format, line_number, raw_line, file_path)
    """
    test_cases = []
    for fmt, path in SAMPLE_FILES.items():
        assert os.path.exists(path), f"Sample file missing: {path}"
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        assert len(lines) >= 10, f"Expected at least 10 lines in {path}, got {len(lines)}"
        for idx, line in enumerate(lines, 1):
            test_cases.append((fmt, idx, line, path))
    return test_cases


ALL_TEST_CASES = load_sample_lines()
detector = FormatDetector()


@pytest.mark.parametrize("expected_format, line_num, raw_line, file_path", ALL_TEST_CASES)
def test_format_detector_classification(expected_format: str, line_num: int, raw_line: str, file_path: str):
    """Test format detection for every sample line across all 9 log formats."""
    result = detector.detect(raw_line)

    assert result.format == expected_format, (
        f"Mismatch in {os.path.basename(file_path)} line {line_num}!\n"
        f"Expected: '{expected_format}', Got: '{result.format}' (Confidence: {result.confidence})\n"
        f"Line: {raw_line!r}"
    )

    if expected_format != "unknown":
        assert result.confidence >= 0.70, (
            f"Low confidence ({result.confidence}) for '{expected_format}' in {os.path.basename(file_path)} line {line_num}!"
        )
    else:
        assert result.confidence == 0.0, "Expected 0.0 confidence for unknown format"


def test_detector_classification_matrix_summary(capsys):
    """Generate and display format detector classification test matrix summary."""
    stats = {}

    for expected_format, path in SAMPLE_FILES.items():
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        
        correct = 0
        confidences = []
        
        for line in lines:
            res = detector.detect(line)
            if res.format == expected_format:
                correct += 1
            confidences.append(res.confidence)
            
        stats[expected_format] = {
            "total": len(lines),
            "correct": correct,
            "accuracy": (correct / len(lines)) * 100.0,
            "avg_confidence": sum(confidences) / len(confidences) if confidences else 0.0
        }

    # Print Matrix Table
    print("\n" + "=" * 75)
    print(f"{'FORMAT CLASSIFICATION TEST MATRIX SUMMARY':^75}")
    print("=" * 75)
    print(f"{'Expected Format':<18} | {'Total':<6} | {'Passed':<6} | {'Accuracy':<10} | {'Avg Confidence':<14}")
    print("-" * 75)

    for fmt, data in stats.items():
        print(
            f"{fmt:<18} | {data['total']:<6} | {data['correct']:<6} | "
            f"{data['accuracy']:>6.1f}%    | {data['avg_confidence']:>10.2f}"
        )
    print("=" * 75)
