from __future__ import annotations

from pathlib import Path

from slimconfig import build_output, plain_output

import verifier
from contract import LogInput, LogOutput
from plugin.log import analyze_log

ACCESS_LINE = (
    '192.168.1.42 - - [10/Oct/2026:13:55:36 +0000] '
    '"GET /api/v1/users HTTP/1.1" 200 1234 "-" '
    '"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"'
)

ERROR_LINE = (
    "2026/10/10 13:55:36 [error] 1234#5678: *9 "
    "connect() failed (111: Connection refused) while connecting to upstream"
)

TIMEOUT_LINE = (
    "2026/10/10 13:55:37 [error] 1234#5678: *10 "
    "upstream timed out (110: Connection timed out) while reading response header"
)


def _run(log_type: str, line: str):
    given = build_output({"log_type": log_type, "line": line}, LogInput)
    made = build_output(plain_output(analyze_log(given, Path("."))), LogOutput)
    return given, made


def test_approves_correct_access_output():
    given, made = _run("access", ACCESS_LINE)
    assert verifier.verify_input("analyze_log", given)["valid"] is True
    assert verifier.verify_output("analyze_log", given, made, ".")["valid"] is True
    assert verifier.verify_task("analyze-log", given, made, None, ".")["valid"] is True


def test_approves_correct_error_output():
    given, made = _run("error", ERROR_LINE)
    assert verifier.verify_input("analyze_log", given)["valid"] is True
    assert verifier.verify_output("analyze_log", given, made, ".")["valid"] is True
    assert verifier.verify_task("analyze-log", given, made, None, ".")["valid"] is True


def test_approves_timeout_category():
    given, made = _run("error", TIMEOUT_LINE)
    assert made.category == "timeout"
    assert verifier.verify_output("analyze_log", given, made, ".")["valid"] is True


def test_refuses_wrong_status():
    given, made = _run("access", ACCESS_LINE)
    made.status = 404
    verdict = verifier.verify_output("analyze_log", given, made, ".")
    assert verdict["valid"] is False
    assert "status" in verdict["message"]


def test_refuses_wrong_kind():
    given, made = _run("access", ACCESS_LINE)
    made.kind = "error"
    verdict = verifier.verify_output("analyze_log", given, made, ".")
    assert verdict["valid"] is False
    assert "kind" in verdict["message"]


def test_refuses_non_null_unused_field():
    given, made = _run("access", ACCESS_LINE)
    made.level = "error"
    verdict = verifier.verify_output("analyze_log", given, made, ".")
    assert verdict["valid"] is False
    assert "level" in verdict["message"]


def test_refuses_wrong_category():
    given, made = _run("error", ERROR_LINE)
    made.category = "unknown"
    verdict = verifier.verify_output("analyze_log", given, made, ".")
    assert verdict["valid"] is False
    assert "category" in verdict["message"]


def test_refuses_category_on_access_log():
    given, made = _run("access", ACCESS_LINE)
    made.category = "connection_refused"
    verdict = verifier.verify_output("analyze_log", given, made, ".")
    assert verdict["valid"] is False
    assert "category" in verdict["message"]


def test_refuses_malformed_input():
    given = build_output({"log_type": "access", "line": "not a log"}, LogInput)
    verdict = verifier.verify_input("analyze_log", given)
    assert verdict["valid"] is False
    assert "Apache Combined" in verdict["message"]


def test_boundary_null_bytes():
    line = (
        '10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] '
        '"GET / HTTP/1.1" 304 - "-" "-"'
    )
    given, made = _run("access", line)
    assert made.bytes_sent is None
    assert verifier.verify_output("analyze_log", given, made, ".")["valid"] is True