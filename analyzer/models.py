"""Data models for log analysis and threat detection."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from ipaddress import IPv4Address
from pydantic import BaseModel, Field, field_validator


class ThreatSeverity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"


@dataclass(frozen=True, slots=True)
class LogEntry:
    """Parsed log entry."""
    timestamp: datetime
    ip_address: IPv4Address
    event_type: str
    raw_line: str
    username: Optional[str] = None


@dataclass(frozen=True, slots=True)
class IPThreatSummary:
    """Aggregated threat summary for a single IP."""
    ip_address: IPv4Address
    failed_attempts: int
    unique_usernames: set[str] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    @property
    def severity(self) -> ThreatSeverity:
        """Determine severity based on attempt count."""
        if self.failed_attempts >= 5:
            return ThreatSeverity.CRITICAL
        elif self.failed_attempts >= 3:
            return ThreatSeverity.HIGH
        elif self.failed_attempts >= 2:
            return ThreatSeverity.MEDIUM
        elif self.failed_attempts >= 1:
            return ThreatSeverity.LOW
        return ThreatSeverity.NONE
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "ip": str(self.ip_address),
            "count": self.failed_attempts,
            "severity": self.severity.value,
            "unique_usernames": list(self.unique_usernames),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class ThreatReport(BaseModel):
    """Complete threat analysis report."""
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    total_ips_analyzed: int = 0
    total_failed_attempts: int = 0
    threats: list[IPThreatSummary] = Field(default_factory=list)
    log_file: str = ""
    
    @field_validator('threats', mode='before')
    @classmethod
def sort_threats(cls, v):
        """Sort threats by severity and count (descending)."""
        if not v:
            return v
        severity_order = {
            ThreatSeverity.CRITICAL: 0,
            ThreatSeverity.HIGH: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.LOW: 3,
            ThreatSeverity.NONE: 4,
        }
        return sorted(v, key=lambda x: (severity_order.get(x.severity, 99), -x.failed_attempts))
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "total_ips_analyzed": self.total_ips_analyzed,
            "total_failed_attempts": self.total_failed_attempts,
            "threats": [t.to_dict() for t in self.threats],
            "log_file": self.log_file,
        }
    
    def get_summary_stats(self) -> dict:
        """Get summary statistics by severity."""
        stats = {s.value: 0 for s in ThreatSeverity}
        for threat in self.threats:
            stats[threat.severity.value] += 1
        return stats