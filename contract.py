"""Each tool's and task's typed input and output (see nanoagent.plugin.v0001.contract): declarations only."""

from dataclasses import dataclass
from enum import Enum
from typing import Annotated

from slimconfig import Output


class Tool(Enum):
    ANALYZE_LOG = "analyze_log"


class Task(Enum):
    ANALYZE_LOG = "analyze-log"


@dataclass
class LogInput(Output):
    log_type: Annotated[str, "Either 'access' or 'error'"]
    line: Annotated[str, "One raw Web server log line"]


@dataclass
class LogOutput(Output):
    kind: Annotated[str, "Either 'access' or 'error', echoing the input"]

    # Shared
    timestamp: Annotated[str | None, "Request or error timestamp, or null if absent"]

    # Access log fields
    remote_addr: Annotated[str | None, "Client IP for an access log, else null"]
    method: Annotated[str | None, "HTTP method for an access log, else null"]
    path: Annotated[str | None, "Request path for an access log, else null"]
    protocol: Annotated[str | None, "HTTP protocol for an access log, else null"]
    status: Annotated[int | None, "HTTP status code for an access log, else null"]
    bytes_sent: Annotated[int | None, "Response size in bytes for an access log, else null"]
    referer: Annotated[str | None, "Referer for an access log, else null"]
    user_agent: Annotated[str | None, "User-Agent for an access log, else null"]

    # Error log fields
    level: Annotated[str | None, "Syslog level for an error log, else null"]
    message: Annotated[str | None, "Error message for an error log, else null"]
    pid: Annotated[int | None, "Process id for an error log, else null"]
    connection: Annotated[str | None, "Connection id like '*9' for an error log, else null"]
    category: Annotated[
        str | None,
        "Semantic error category for an error log: connection_refused, permission_denied, "
        "file_not_found, timeout, upstream_error, or unknown; null for an access log",
    ]


TOOLS = {Tool.ANALYZE_LOG: (LogInput, LogOutput)}
TASKS = {Task.ANALYZE_LOG: (LogInput, LogOutput)}