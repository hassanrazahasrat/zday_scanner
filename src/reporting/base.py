"""
ZDay Scanner - Reporting Base Classes
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass

from src.core.models import ScanResult, Vulnerability, Technology


@dataclass
class ReportOptions:
    """Options for report generation"""
    include_technologies: bool = True
    include_vulnerabilities: bool = True
    include_evidence: bool = True
    include_remediation: bool = True
    min_severity: str = "info"
    template: str = "default"
    custom_fields: Dict[str, Any] = None


class BaseReporter(ABC):
    """Abstract base reporter"""

    def __init__(self, options: ReportOptions = None):
        self.options = options or ReportOptions()

    @abstractmethod
    def generate(self, result: ScanResult) -> str:
        """Generate report from scan result"""
        pass

    @abstractmethod
    def get_extension(self) -> str:
        """Get file extension for this report format"""
        pass

    def _filter_vulnerabilities(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Filter vulnerabilities by minimum severity"""
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_idx = severity_order.index(self.options.min_severity.lower())

        return [v for v in vulns if severity_order.index(v.severity.value) >= min_idx]

    def _group_vulns_by_severity(self, vulns: List[Vulnerability]) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by severity"""
        groups = {}
        for vuln in vulns:
            sev = vuln.severity.value
            if sev not in groups:
                groups[sev] = []
            groups[sev].append(vuln)
        return groups

    def _group_tech_by_category(self, techs: List[Technology]) -> Dict[str, List[Technology]]:
        """Group technologies by category"""
        groups = {}
        for tech in techs:
            cat = tech.category
            if cat not in groups:
                groups[cat] = []
            groups[cat].append(tech)
        return groups

    def _count_by_severity(self, vulns: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {}
        for vuln in vulns:
            sev = vuln.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_by_type(self, vulns: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by type"""
        counts = {}
        for vuln in vulns:
            typ = vuln.type.value
            counts[typ] = counts.get(typ, 0) + 1
        return counts

