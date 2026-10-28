from __future__ import annotations

import re

from contract import LogOutput

from .checks import result

ACCESS_RE = re.compile(
    r'^(?P<remote_addr>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes_sent>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

ERROR_RE = re.compile(
    r'^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
    r'\[(?P<level>\w+)\] (?P<pid>\d+)#\d+: '
    r'(?:\*(?P<connection>\d+) )?(?P<message>.+)$'
)


def _none_if_dash(value: str) -> str | None:
    return None if value == "-" else value


def _expected(input_value) -> LogOutput:
    """Independently parse the input into the output it must produce."""
    if input_value.log_type == "access":
        match = ACCESS_RE.match(input_value.line)
        if not match:
            raise ValueError("line is not in Apache Combined Log Format")
        fields = match.groupdict()
        bytes_sent = None if fields["bytes_sent"] == "-" else int(fields["bytes_sent"])
        return LogOutput(
            kind="access",
            timestamp=fields["timestamp"],
            remote_addr=fields["remote_addr"],
            method=fields["method"],
            path=fields["path"],
            protocol=fields["protocol"],
            status=int(fields["status"]),
            bytes_sent=bytes_sent,
            referer=_none_if_dash(fields["referer"]),
            user_agent=_none_if_dash(fields["user_agent"]),
            level=None,
            message=None,
            pid=None,
            connection=None,
        )

    if input_value.log_type == "error":
        match = ERROR_RE.match(input_value.line)
        if not match:
            raise ValueError("line is not in Nginx error log format")
        fields = match.groupdict()
        connection = f"*{fields['connection']}" if fields["connection"] else None
        return LogOutput(
            kind="error",
            timestamp=fields["timestamp"],
            remote_addr=None,
            method=None,
            path=None,
            protocol=None,
            status=None,
            bytes_sent=None,
            referer=None,
            user_agent=None,
            level=fields["level"],
            message=fields["message"],
            pid=int(fields["pid"]),
            connection=connection,
        )

    raise ValueError("log_type must be 'access' or 'error'")


def _compare(expected: LogOutput, actual: LogOutput) -> str | None:
    for field in expected.__dataclass_fields__:
        exp = getattr(expected, field)
        act = getattr(actual, field)
        if exp != act:
            return f"{field}: expected {exp!r}, got {act!r}"
    return None


def verify_input(value):
    if value.log_type not in ("access", "error"):
        return result(False, "log_type must be 'access' or 'error'")
    if not value.line.strip():
        return result(False, "line must not be empty")
    try:
        _expected(value)
    except ValueError as exc:
        return result(False, str(exc))
    return result(True, "input is valid")


def verify_output(input_value, output_value, workspace):
    try:
        expected = _expected(input_value)
    except ValueError as exc:
        return result(False, f"input cannot be parsed: {exc}")
    problem = _compare(expected, output_value)
    if problem:
        return result(False, problem)
    return result(True, "log is parsed and classified correctly")


def verify_task(arguments, output, reference, workspace):
    return verify_output(arguments, output, workspace)