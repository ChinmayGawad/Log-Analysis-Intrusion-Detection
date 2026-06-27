"""Log parsing functionality."""

import re
from datetime import datetime
from ipaddress import IPv4Address, AddressValueError
from pathlib import Path
from typing import Iterator, Optional

from .models import LogEntry


class LogParser:
    """Parse log files and extract structured log entries."""
    
    # Default pattern for failed login attempts
    DEFAULT_PATTERN = re.compile(
        r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(\d+\.\d+\.\d+\.\d+)\] (FAILED LOGIN) user: (\w+)"
    )
    
    # Alternative pattern without username
    SIMPLE_PATTERN = re.compile(
        r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(\d+\.\d+\.\d+\.\d+)\] (FAILED LOGIN)"
    )

    def __init__(self, pattern: Optional[str] = None):
        """Initialize parser with custom regex pattern."""
        if pattern:
            self.pattern = re.compile(pattern)
            self.simple_pattern = None
        else:
            self.pattern = self.DEFAULT_PATTERN
            self.simple_pattern = self.SIMPLE_PATTERN
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line."""
        line = line.strip()
        if not line:
            return None
        
        # Try primary pattern first
        match = self.pattern.match(line)
        if match:
            timestamp_str, ip_str, event_type, username = match.groups()
            return self._create_entry(timestamp_str, ip_str, event_type, username, line)
        
        # Try simple pattern
        if self.simple_pattern:
            match = self.simple_pattern.match(line)
            if match:
                timestamp_str, ip_str, event_type = match.groups()
                return self._create_entry(timestamp_str, ip_str, event_type, None, line)
        
        return None
    
    def _create_entry(self, timestamp_str: str, ip_str: str, event_type: str, 
                       username: Optional[str], raw_line: str) -> Optional[LogEntry]:
        """Create LogEntry from parsed components."""
        try:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            ip_address = IPv4Address(ip_str)
            return LogEntry(
                timestamp=timestamp,
                ip_address=ip_address,
                event_type=event_type,
                raw_line=raw_line,
                username=username,
            )
        except (ValueError, AddressValueError) as e:
            # Log parsing error but don't crash
            return None
    
    def parse_file(self, file_path: Path) -> Iterator[LogEntry]:
        """Parse log file and yield valid entries."""
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                entry = self.parse_line(line)
                if entry:
                    yield entry
    
    def parse_lines(self, lines: list[str]) -> list[LogEntry]:
        """Parse multiple lines and return valid entries."""
        entries = []
        for line in lines:
            entry = self.parse_line(line)
            if entry:
                entries.append(entry)
        return entries