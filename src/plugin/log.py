from __future__ import annotations

import re
from pathlib import Path

from contract import LogInput, LogOutput

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


def analyze_log(log: LogInput, _workspace: Path) -> LogOutput:
    if log.log_type == "access":
        match = ACCESS_RE.match(log.line)
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

    if log.log_type == "error":
        match = ERROR_RE.match(log.line)
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