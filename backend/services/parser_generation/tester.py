import re
from typing import List, Dict, Any
from backend.models.parser import ParserCandidate, ParserTestCase, ParserValidationResult
from backend.services.parsing.detector import FormatDetector
from backend.services.parsing.cef_parser import CEFParser
from backend.services.parsing.leef_parser import LEEFParser
from backend.services.parsing.json_parser import JSONParser
from backend.services.parsing.kv_parser import KVParser
from backend.services.parsing.syslog_parser import SyslogParser

class ParserTester:
    """
    USP 1 Validation Gate: Tests candidate parsers against multiple sample logs.
    Never allows silent approval of untested parsers.
    """

    @classmethod
    def test_candidate(cls, candidate: ParserCandidate, sample_logs: List[str]) -> ParserCandidate:
        if not sample_logs:
            raise ValueError("No test samples provided.")

        results: List[ParserTestCase] = []
        passed_count = 0
        all_unmapped = set()
        validation_errors = []

        regex_compiled = None
        if candidate.rule.format_type == "regex" and candidate.rule.regex_pattern:
            try:
                regex_compiled = re.compile(candidate.rule.regex_pattern)
            except Exception as e:
                validation_errors.append(f"Invalid regex pattern: {str(e)}")

        for line in sample_logs:
            line_str = line.strip()
            if not line_str:
                continue

            extracted: Dict[str, Any] = {}
            success = False
            error_msg = None

            try:
                if candidate.rule.format_type == "cef":
                    success, extracted = CEFParser.parse(line_str)
                elif candidate.rule.format_type == "leef":
                    success, extracted = LEEFParser.parse(line_str)
                elif candidate.rule.format_type == "json":
                    success, extracted = JSONParser.parse(line_str)
                elif candidate.rule.format_type == "kv":
                    success, extracted = KVParser.parse(line_str)
                elif candidate.rule.format_type == "syslog":
                    success, extracted = SyslogParser.parse(line_str)
                elif candidate.rule.format_type == "regex" and regex_compiled:
                    match = regex_compiled.search(line_str)
                    if match:
                        success = True
                        extracted = match.groupdict()
                    else:
                        success = False
                        error_msg = "Pattern did not match sample line."
                else:
                    # Fallback to detector
                    fmt, extracted = FormatDetector.detect_and_parse(line_str)
                    success = bool(extracted and fmt != "unstructured")

                if success:
                    passed_count += 1
                    # Find unmapped fields
                    mapped_sources = {m.source_field for m in candidate.rule.mappings}
                    for k in extracted.keys():
                        if k not in mapped_sources and not k.startswith("_"):
                            all_unmapped.add(k)
                else:
                    if not error_msg:
                        error_msg = f"Failed to parse with format '{candidate.rule.format_type}'"
            except Exception as e:
                success = False
                error_msg = str(e)

            results.append(ParserTestCase(
                sample_log=line_str,
                passed=success,
                extracted_fields=extracted if success else None,
                error_message=error_msg
            ))

        total = len(results)
        failed = total - passed_count
        accuracy = round((passed_count / total) * 100.0, 1) if total > 0 else 0.0

        val_result = ParserValidationResult(
            total_samples=total,
            passed_samples=passed_count,
            failed_samples=failed,
            accuracy_score=accuracy,
            sample_results=results,
            unmapped_fields=sorted(list(all_unmapped)),
            validation_errors=validation_errors
        )

        candidate.validation = val_result
        candidate.tested = True
        return candidate
