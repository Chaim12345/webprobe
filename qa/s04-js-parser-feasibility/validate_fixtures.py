#!/usr/bin/env python3
"""Validate fixture arithmetic only; this is not a JavaScript parser test."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = json.loads((ROOT / "fixtures.json").read_text())
fixtures = {item["id"]: item for item in spec["fixtures"]}

multi = fixtures["multibyte_offsets"]
raw = multi["source"].encode()
assert len(raw) == multi["source_utf8_bytes"]
for key in ("member_expression", "identifier"):
    expected = multi["expected"][key]
    assert raw[expected["start"] : expected["end"]].decode() == expected["text"]

malformed = fixtures["malformed_fragment_valid_sibling"]
combined = malformed["combined_source_for_recovery_observation"].encode()
start = malformed["expected"]["good_member_utf8_start_in_combined"]
end = malformed["expected"]["good_member_utf8_end_in_combined"]
assert combined[start:end] == b"window.name"
assert combined[end:] == b";"
assert malformed["expected"]["trailing_semicolon_byte"] == end

escape = fixtures["escape_decoding"]
raw = escape["source"].encode()
assert raw[escape["raw_literal_start"] : escape["raw_literal_end"]].decode() == escape["raw_literal_source"]
assert escape["expected_decoded_value"].encode().hex() == escape["expected_decoded_utf8_hex"]
assert escape["expected_decoded_value"] == "line\nAB"

large = fixtures["bounded_large_input"]
source = "/*" + ("x" * (1048576 - 6)) + "*/\n;"
assert len(source.encode()) == large["expected_utf8_bytes"] == 1048576
assert hashlib.sha256(source.encode()).hexdigest() == large["expected_sha256"]
assert len((source + "x").encode()) > spec["common_requirements"]["reject_input_bytes_above"]

result = {
    "status": "PASS_FIXTURE_ARITHMETIC_ONLY",
    "javascript_parser_tests": {"run": 0, "passed": 0, "failed": 0, "not_run_families": 4},
    "multibyte_member_utf8_bytes": [19, 30],
    "multibyte_identifier_utf8_bytes": [19, 25],
    "malformed_sibling_combined_utf8_bytes": [17, 28],
    "raw_literal_utf8_bytes": [16, 34],
    "decoded_utf8_hex": escape["expected_decoded_utf8_hex"],
    "large_input": {"bytes": len(source.encode()), "sha256": hashlib.sha256(source.encode()).hexdigest()},
}
(ROOT / "fixture-validation.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
