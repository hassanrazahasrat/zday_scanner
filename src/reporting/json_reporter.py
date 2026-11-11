"""
ZDay Scanner - JSON Reporter
Machine-readable JSON output
"""
import json
from typing import Dict, Any

from src.reporting.base import BaseReporter, ReportOptions
from src.core.models import ScanResult


class JSONReporter(BaseReporter):
    """JSON report generator"""

    def get_extension(self) -> str:
        return ".json"

    def generate(self, result: ScanResult) -> str:
        """Generate JSON report"""

        # Filter vulnerabilities
        vulns = self._filter_vulnerabilities(result.vulnerabilities)

        report = {
            "scan_info": {
                "target": str(result.target.url),
                "scan_id": result.scan_id,
                "start_time": result.start_time.isoformat() if result.start_time else None,
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "duration": result.duration,
                "scanner_version": "1.0.0",
            },
            "summary": {
                "total_vulnerabilities": len(vulns),
                "by_severity": self._count_by_severity(vulns),
                "by_type": self._count_by_type(vulns),
                "technologies_detected": len(result.technologies),
            },
            "technologies": [],
            "vulnerabilities": [],
        }

        # Add technologies
        if self.options.include_technologies:
            for tech in result.technologies:
                report["technologies"].append({
                    "name": tech.name,
                    "version": tech.version,
                    "category": tech.category,
                    "confidence": tech.confidence,
                    "evidence": tech.evidence if self.options.include_evidence else [],
                    "cpe": tech.cpe,
                })

        # Add vulnerabilities
        if self.options.include_vulnerabilities:
            for vuln in vulns:
                vuln_data = {
                    "type": vuln.type.value,
                    "severity": vuln.severity.value,
                    "title": vuln.title,
                    "description": vuln.description,
                    "location": vuln.location,
                    "parameter": vuln.parameter,
                    "payload": vuln.payload,
                    "evidence": vuln.evidence if self.options.include_evidence else None,
                    "remediation": vuln.remediation if self.options.include_remediation else None,
                    "references": vuln.references,
                    "cwe": vuln.cwe,
                    "cvss": vuln.cvss,
                    "cvss_score": vuln.cvss_score,
                    "tags": vuln.tags,
                    "scanner_module": vuln.scanner_module,
                    "confidence": vuln.confidence,
                }
                report["vulnerabilities"].append(vuln_data)

        return json.dumps(report, indent=2, default=str)

    def _count_by_severity(self, vulns) -> Dict[str, int]:
        counts = {}
        for v in vulns:
            sev = v.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_by_type(self, vulns) -> Dict[str, int]:
        counts = {}
        for v in vulns:
            t = v.type.value
            counts[t] = counts.get(t, 0) + 1
        return counts
