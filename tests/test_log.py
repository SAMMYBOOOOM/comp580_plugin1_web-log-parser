from __future__ import annotations

from pathlib import Path

import pytest

from contract import LogInput
from plugin.log import analyze_log, categorize_error

ACCESS_LINE = (
    '192.168.1.42 - - [10/Oct/2026:13:55:36 +0000] '
    '"GET /api/v1/users HTTP/1.1" 200 1234 "-" '
    '"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"'
)

ERROR_LINE = (
    "2026/10/10 13:55:36 [error] 1234#5678: *9 "
    "connect() failed (111: Connection refused) while connecting to upstream"
)


def test_parses_access_log():
    out = analyze_log(LogInput(log_type="access", line=ACCESS_LINE), Path("."))
    assert out.kind == "access"
    assert out.remote_addr == "192.168.1.42"
    assert out.timestamp == "10/Oct/2026:13:55:36 +0000"
    assert out.method == "GET"
    assert out.path == "/api/v1/users"
    assert out.protocol == "HTTP/1.1"
    assert out.status == 200
    assert out.bytes_sent == 1234
    assert out.referer is None
    assert out.user_agent.startswith("Mozilla/5.0")
    assert out.level is None
    assert out.category is None


def test_parses_error_log():
    out = analyze_log(LogInput(log_type="error", line=ERROR_LINE), Path("."))
    assert out.kind == "error"
    assert out.timestamp == "2026/10/10 13:55:36"
    assert out.level == "error"
    assert out.pid == 1234
    assert out.connection == "*9"
    assert out.message.startswith("connect() failed")
    assert out.category == "connection_refused"
    assert out.remote_addr is None


def test_boundary_missing_bytes_referer_user_agent():
    line = (
        '10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] '
        '"GET / HTTP/1.1" 304 - "-" "-"'
    )
    out = analyze_log(LogInput(log_type="access", line=line), Path("."))
    assert out.bytes_sent is None
    assert out.referer is None
    assert out.user_agent is None
    assert out.category is None


def test_rejects_unknown_log_type():
    with pytest.raises(ValueError, match="log_type"):
        analyze_log(LogInput(log_type="syslog", line=ACCESS_LINE), Path("."))


def test_rejects_malformed_line():
    with pytest.raises(ValueError, match="Apache Combined"):
        analyze_log(LogInput(log_type="access", line="not a log line"), Path("."))


@pytest.mark.parametrize(
    "message, expected",
    [
        (
            "connect() failed (111: Connection refused) while connecting to upstream",
            "connection_refused",
        ),
        (
            'open() "/var/www" failed (13: Permission denied)',
            "permission_denied",
        ),
        (
            'open() "/var/www/missing.html" failed (2: No such file or directory)',
            "file_not_found",
        ),
        (
            "upstream timed out (110: Connection timed out) while reading response header",
            "timeout",
        ),
        (
            "upstream prematurely closed connection while reading response header",
            "upstream_error",
        ),
        (
            "something completely unexpected happened",
            "unknown",
        ),
    ],
)
def test_categorize_error(message, expected):
    assert categorize_error(message) == expected