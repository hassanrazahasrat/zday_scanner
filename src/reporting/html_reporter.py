"""
ZDay Scanner - HTML Reporter
Interactive HTML report with charts
"""
import json
from pathlib import Path
from typing import Dict, Any, List

from src.reporting.base import BaseReporter, ReportOptions
from src.core.models import ScanResult, Vulnerability, Technology


class HTMLReporter(BaseReporter):
    """HTML report generator with interactive charts"""

    def get_extension(self) -> str:
        return ".html"

    def generate(self, result: ScanResult) -> str:
        """Generate HTML report"""

        vulns = self._filter_vulnerabilities(result.vulnerabilities)

        # Prepare data for template
        vuln_data = []
        for vuln in vulns:
            vuln_data.append({
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
            })

        tech_data = []
        for tech in result.technologies:
            tech_data.append({
                "name": tech.name,
                "version": tech.version,
                "category": tech.category,
                "confidence": tech.confidence,
                "evidence": tech.evidence if self.options.include_evidence else [],
                "cpe": tech.cpe,
            })

        summary = {
            "total_vulnerabilities": len(vulns),
            "by_severity": self._count_by_severity(vulns),
            "by_type": self._count_by_type(vulns),
            "technologies_detected": len(result.technologies),
        }

        scan_info = {
            "target": str(result.target.url),
            "scan_id": result.scan_id,
            "start_time": result.start_time.isoformat() if result.start_time else None,
            "end_time": result.end_time.isoformat() if result.end_time else None,
            "duration": result.duration,
        }

        # Generate HTML using template file
        return self._build_html(scan_info, summary, vuln_data, tech_data)

    def _build_html(self, scan_info: Dict, summary: Dict, vuln_data: List, tech_data: List) -> str:
        """Build HTML report from template"""

        # JSON data for JavaScript
        data_json = json.dumps({
            "scan_info": scan_info,
            "summary": summary,
            "vulnerabilities": vuln_data,
            "technologies": tech_data,
        }, default=str)

        target = scan_info["target"]
        scan_id = scan_info["scan_id"][:8] + "..."
        duration = scan_info["duration"]

        crit = summary["by_severity"].get("critical", 0)
        high = summary["by_severity"].get("high", 0)
        medium = summary["by_severity"].get("medium", 0)
        low = summary["by_severity"].get("low", 0)
        info = summary["by_severity"].get("info", 0)
        total_vulns = summary["total_vulnerabilities"]
        total_techs = summary["technologies_detected"]

        # Load template
        template_path = Path(__file__).parent / "html_template.html"
        with open(template_path, "r") as f:
            template = f.read()

        # Format template
        html = template.format(
            target=target,
            scan_id=scan_id,
            duration=duration,
            crit=crit,
            high=high,
            medium=medium,
            low=low,
            info=info,
            total_vulns=total_vulns,
            total_techs=total_techs,
            data_json=data_json,
        )

        return html
