"""
parser.py - Log Parsing Module
================================
Handles reading and parsing of Linux auth.log files.
Extracts IP addresses, timestamps, usernames, and login status
from SSH authentication log entries using regex pattern matching.

Author: SOC Analyst Toolkit
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────
#  Data Model
# ─────────────────────────────────────────────

@dataclass
class LogEntry:
    """Represents a single parsed log line."""
    raw_line: str
    timestamp: Optional[str]
    hostname: Optional[str]
    process: Optional[str]
    pid: Optional[int]
    ip_address: Optional[str]
    username: Optional[str]
    port: Optional[int]
    status: str          # "failed" | "success" | "invalid_user"
    year: int = field(default_factory=lambda: datetime.now().year)

    def __str__(self):
        return (
            f"[{self.timestamp}] {self.status.upper():12s} | "
            f"User: {self.username or 'unknown':15s} | "
            f"IP: {self.ip_address or 'N/A':18s} | "
            f"Port: {self.port or 'N/A'}"
        )


# ─────────────────────────────────────────────
#  Regex Patterns for auth.log formats
# ─────────────────────────────────────────────

# Pattern: Failed password for <user> from <ip> port <port>
PATTERN_FAILED = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+"          # e.g. Apr 13 08:01:12
    r"(?P<hostname>\S+)\s+"                               # hostname
    r"(?P<process>\S+?)\[(?P<pid>\d+)\]:\s+"             # process[pid]:
    r"Failed password for (?:invalid user )?"             # optional 'invalid user'
    r"(?P<username>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+)\s+"
    r"port\s+(?P<port>\d+)"
)

# Pattern: Accepted password/publickey for <user> from <ip> port <port>
PATTERN_SUCCESS = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)\[(?P<pid>\d+)\]:\s+"
    r"Accepted (?:password|publickey|keyboard-interactive)\s+"
    r"for\s+(?P<username>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+)\s+"
    r"port\s+(?P<port>\d+)"
)

# Pattern: Invalid user <user> from <ip>
PATTERN_INVALID = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)\[(?P<pid>\d+)\]:\s+"
    r"Invalid user\s+(?P<username>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+)"
)


# ─────────────────────────────────────────────
#  Parser Class
# ─────────────────────────────────────────────

class LogParser:
    """
    Parses Linux auth.log files and produces structured LogEntry objects.

    Supports:
      - Failed SSH password attempts
      - Successful SSH logins (password + publickey)
      - Invalid user connection attempts
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.entries: list[LogEntry] = []
        self.parse_errors: int = 0
        self.total_lines: int = 0

    # ── Public Interface ──────────────────────

    def parse(self) -> list[LogEntry]:
        """
        Read and parse the log file.
        Returns a list of LogEntry objects.
        Raises FileNotFoundError if the log file doesn't exist.
        """
        try:
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    self.total_lines += 1
                    entry = self._parse_line(line)
                    if entry:
                        self.entries.append(entry)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"[ERROR] Log file not found: '{self.filepath}'\n"
                "        Verify the path and try again."
            )
        return self.entries

    def get_stats(self) -> dict:
        """Return basic parsing statistics."""
        failed  = sum(1 for e in self.entries if e.status == "failed")
        success = sum(1 for e in self.entries if e.status == "success")
        invalid = sum(1 for e in self.entries if e.status == "invalid_user")
        return {
            "total_lines":   self.total_lines,
            "parsed_entries": len(self.entries),
            "failed":        failed,
            "success":       success,
            "invalid_user":  invalid,
            "parse_errors":  self.parse_errors,
        }

    # ── Internal Helpers ─────────────────────

    def _parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Try each regex pattern in priority order.
        Returns a LogEntry on match, None otherwise.
        """
        # 1. Check for successful login
        m = PATTERN_SUCCESS.search(line)
        if m:
            return self._build_entry(m, line, "success")

        # 2. Check for failed password
        m = PATTERN_FAILED.search(line)
        if m:
            return self._build_entry(m, line, "failed")

        # 3. Check for invalid user probe
        m = PATTERN_INVALID.search(line)
        if m:
            return self._build_entry(m, line, "invalid_user")

        # Line did not match any known pattern — not an error, just irrelevant
        return None

    @staticmethod
    def _build_entry(match: re.Match, raw_line: str, status: str) -> LogEntry:
        """Construct a LogEntry from a regex match object."""
        gd = match.groupdict()
        try:
            pid = int(gd.get("pid", 0))
        except (ValueError, TypeError):
            pid = None

        try:
            port = int(gd.get("port", 0))
        except (ValueError, TypeError):
            port = None

        return LogEntry(
            raw_line=raw_line,
            timestamp=gd.get("timestamp"),
            hostname=gd.get("hostname"),
            process=gd.get("process"),
            pid=pid,
            ip_address=gd.get("ip"),
            username=gd.get("username"),
            port=port,
            status=status,
        )
