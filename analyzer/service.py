"""High-level analysis service combining parsing and detection."""

from pathlib import Path
from typing import Optional

from .models import ThreatReport, IPThreatSummary
from .parser import LogParser
from .detector import ThreatDetector, ThresholdConfig


class AnalysisService:
    """Orchestrate log analysis workflow."""
    
    def __init__(
        self,
        parser: Optional[LogParser] = None,
        detector: Optional[ThreatDetector] = None,
    ):
        """Initialize service with optional custom components."""
        self.parser = parser or LogParser()
        self.detector = detector or ThreatDetector()
    
    def analyze_file(self, file_path: Path) -> ThreatReport:
        """Analyze a log file and return a complete threat report."""
        entries = list(self.parser.parse_file(file_path))
        threats = self.detector.analyze(entries)
        
        return ThreatReport(
            total_ips_analyzed=len(threats),
            total_failed_attempts=sum(t.failed_attempts for t in threats),
            threats=threats,
            log_file=str(file_path),
        )
    
    def analyze_lines(self, lines: list[str]) -> ThreatReport:
        """Analyze log lines directly."""
        entries = self.parser.parse_lines(lines)
        threats = self.detector.analyze(entries)
        
        return ThreatReport(
            total_ips_analyzed=len(threats),
            total_failed_attempts=sum(t.failed_attempts for t in threats),
            threats=threats,
            log_file="<inline>",
        )
    
    def get_threat_summary(self, file_path: Path) -> dict:
        """Get a quick summary without full report details."""
        report = self.analyze_file(file_path)
        return {
            "total_threats": report.total_ips_analyzed,
            "total_attempts": report.total_failed_attempts,
            "by_severity": report.get_summary_stats(),
            "top_threats": [t.to_dict() for t in report.threats[:10]],
        }