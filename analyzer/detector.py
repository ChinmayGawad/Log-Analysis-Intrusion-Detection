"""Threat detection logic."""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address
from typing import Optional

from .models import IPThreatSummary, LogEntry, ThreatSeverity


@dataclass(slots=True)
class ThresholdConfig:
    """Threshold configuration for threat levels."""
    critical: int = 5
    high: int = 3
    medium: int = 1
    low: int = 0  # 1+ attempts
    
    def get_severity(self, count: int) -> ThreatSeverity:
        """Determine severity based on count."""
        if count >= self.critical:
            return ThreatSeverity.CRITICAL
        elif count >= self.high:
            return ThreatSeverity.HIGH
        elif count >= self.medium:
            return ThreatSeverity.MEDIUM
        elif count >= self.low:
            return ThreatSeverity.LOW
        return ThreatSeverity.NONE


class ThreatDetector:
    """Detect threats from parsed log entries."""
    
    def __init__(self, thresholds: Optional[ThresholdConfig] = None):
        """Initialize detector with custom thresholds."""
        self.thresholds = thresholds or ThresholdConfig()
    
    def analyze(self, entries: list[LogEntry]) -> list[IPThreatSummary]:
        """Analyze log entries and return threat summaries per IP."""
        # Aggregate by IP
        ip_data: dict[IPv4Address, dict] = defaultdict(lambda: {
            "count": 0,
            "usernames": set(),
            "first_seen": None,
            "last_seen": None,
        })
        
        for entry in entries:
            data = ip_data[entry.ip_address]
            data["count"] += 1
            if entry.username:
                data["usernames"].add(entry.username)
            
            if data["first_seen"] is None or entry.timestamp < data["first_seen"]:
                data["first_seen"] = entry.timestamp
            if data["last_seen"] is None or entry.timestamp > data["last_seen"]:
                data["last_seen"] = entry.timestamp
        
        # Build threat summaries
        threats = []
        for ip, data in ip_data.items():
            severity = self.thresholds.get_severity(data["count"])
            if severity != ThreatSeverity.NONE:
                threats.append(IPThreatSummary(
                    ip_address=ip,
                    failed_attempts=data["count"],
                    unique_usernames=data["usernames"],
                    first_seen=data["first_seen"],
                    last_seen=data["last_seen"],
                ))
        
        # Sort by severity and count
        severity_order = {
            ThreatSeverity.CRITICAL: 0,
            ThreatSeverity.HIGH: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.LOW: 3,
        }
        threats.sort(key=lambda x: (severity_order.get(x.severity, 99), -x.failed_attempts))
        
        return threats