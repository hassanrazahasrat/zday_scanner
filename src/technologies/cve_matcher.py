"""
ZDay Scanner - CVE Matcher
Matches detected technologies against CVE database
"""
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
# from packaging import version  # Not available in Pyodide

from src.core.models import Technology, Vulnerability, VulnerabilityType, Severity


@dataclass
class CVEEntry:
    """CVE database entry"""
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cwe: str
    affected_products: List[Dict[str, Any]]
    references: List[str]
    published_date: str
    updated_date: str


@dataclass
class CVEMatch:
    """A CVE match result"""
    cve: CVEEntry
    technology: Technology
    matched_version: str
    confidence: float


class CVEMatcher:
    """Matches technologies against CVE database"""

    def __init__(self, cve_db_path: Optional[str] = None):
        self.cve_db: List[CVEEntry] = []
        self._index: Dict[str, List[CVEEntry]] = {}  # product -> CVEs
        self.load_database(cve_db_path)

    def load_database(self, path: Optional[str] = None):
        """Load CVE database from file or use built-in"""
        if path and Path(path).exists():
            self._load_from_file(path)
        else:
            self._load_builtin()
        self._build_index()

    def _load_from_file(self, path: str):
        """Load CVE database from JSON file"""
        with open(path, 'r') as f:
            data = json.load(f)

        self.cve_db = []
        for item in data:
            self.cve_db.append(CVEEntry(
                cve_id=item["cve_id"],
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
                cvss_score=item["cvss_score"],
                cvss_vector=item["cvss_vector"],
                cwe=item["cwe"],
                affected_products=item["affected_products"],
                references=item["references"],
                published_date=item["published_date"],
                updated_date=item["updated_date"],
            ))

    def _load_builtin(self):
        """Load built-in CVE database (sample)"""
        builtin_cves = [
            {
                "cve_id": "CVE-2021-44228",
                "title": "Apache Log4j2 Remote Code Execution",
                "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "severity": "critical",
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "cwe": "CWE-502",
                "affected_products": [
                    {"vendor": "apache", "product": "log4j", "versions": ["2.0-beta9", "2.15.0"]}
                ],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                "published_date": "2021-12-10",
                "updated_date": "2021-12-28",
            },
            {
                "cve_id": "CVE-2022-22965",
                "title": "Spring Framework RCE (Spring4Shell)",
                "description": "Spring Framework 5.3.0 to 5.3.17, 5.2.0 to 5.2.19, and older versions allow RCE via data binding.",
                "severity": "critical",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe": "CWE-94",
                "affected_products": [
                    {"vendor": "spring", "product": "spring-framework", "versions": ["5.3.0", "5.3.17"]}
                ],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
                "published_date": "2022-03-31",
                "updated_date": "2022-04-01",
            },
            {
                "cve_id": "CVE-2021-41773",
                "title": "Apache HTTP Server Path Traversal",
                "description": "Apache HTTP Server 2.4.49 and 2.4.50 path traversal and RCE.",
                "severity": "critical",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe": "CWE-22",
                "affected_products": [
                    {"vendor": "apache", "product": "http_server", "versions": ["2.4.49", "2.4.50"]}
                ],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                "published_date": "2021-10-05",
                "updated_date": "2021-10-07",
            },
            {
                "cve_id": "CVE-2022-3590",
                "title": "WordPress < 6.0.1 Authenticated Stored XSS",
                "description": "WordPress before 6.0.1 allows authenticated users to inject arbitrary web script via crafted posts.",
                "severity": "medium",
                "cvss_score": 5.4,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                "cwe": "CWE-79",
                "affected_products": [
                    {"vendor": "wordpress", "product": "wordpress", "versions": ["0", "6.0.1"]}
                ],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-3590"],
                "published_date": "2022-08-30",
                "updated_date": "2022-08-30",
            },
            {
                "cve_id": "CVE-2018-7600",
                "title": "Drupalgeddon2 - Remote Code Execution",
                "description": "Drupal 6.x, 7.x, 8.x before 8.5.1 allow remote code execution.",
                "severity": "critical",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe": "CWE-94",
                "affected_products": [
                    {"vendor": "drupal", "product": "drupal", "versions": ["6.0", "7.58", "8.5.0"]}
                ],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-7600"],
                "published_date": "2018-03-28",
                "updated_date": "2018-04-25",
            },
            {
                "cve_id": "CVE-2020-11022",
                "title": "jQuery < 3.5.0 XSS",
                "description": "jQuery before 3.5.0 allows XSS via HTML parsing.",
                "severity": "medium",
                "cvss_score": 6.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cwe": "CWE-79",
                "affected_products": [
                    {"vendor": "jquery", "product": "jquery", "versions": ["0", "3.5.0"]}
                ],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-11022"],
                "published_date": "2020-04-29",
                "updated_date": "2020-05-01",
            },
            {
                "cve_id": "CVE-2019-8331",
                "title": "Bootstrap < 3.4.1 XSS",
                "description": "Bootstrap before 3.4.1 allows XSS via data-target attribute.",
                "severity": "medium",
                "cvss_score": 6.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cwe": "CWE-79",
                "affected_products": [
                    {"vendor": "bootstrap", "product": "bootstrap", "versions": ["0", "3.4.1"]}
                ],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-8331"],
                "published_date": "2019-02-13",
                "updated_date": "2019-02-13",
            }
        ]

        self.cve_db = []
        for item in builtin_cves:
            self.cve_db.append(CVEEntry(
                cve_id=item["cve_id"],
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
                cvss_score=item["cvss_score"],
                cvss_vector=item["cvss_vector"],
                cwe=item["cwe"],
                affected_products=item["affected_products"],
                references=item["references"],
                published_date=item["published_date"],
                updated_date=item["updated_date"],
            ))

    def _build_index(self):
        """Build lookup index for faster matching"""
        self._index = {}
        for cve in self.cve_db:
            for product in cve.affected_products:
                key = f"{product['vendor'].lower()}:{product['product'].lower()}"
                if key not in self._index:
                    self._index[key] = []
                self._index[key].append(cve)

    def match(self, technology: Technology) -> List[CVEMatch]:
        """Match a technology against CVE database"""
        matches = []

        if not technology.version:
            return matches

        # Find relevant CVEs
        key = f"{technology.name.lower().replace(' ', '')}:{technology.category.lower()}"
        # Try multiple key formats
        keys_to_try = [
            key,
            f"{technology.name.lower()}:{technology.category.lower()}",
            f"{technology.name.lower()}:server",
            f"{technology.name.lower()}:framework",
            f"{technology.name.lower()}:cms",
            f"{technology.name.lower()}:library",
        ]

        relevant_cves = []
        for k in keys_to_try:
            if k in self._index:
                relevant_cves.extend(self._index[k])

        # Deduplicate
        seen = set()
        unique_cves = []
        for cve in relevant_cves:
            if cve.cve_id not in seen:
                seen.add(cve.cve_id)
                unique_cves.append(cve)

        # Check version ranges
        tech_version = technology.version
        for cve in unique_cves:
            for product in cve.affected_products:
                versions = product.get("versions", [])
                if len(versions) >= 2:
                    min_ver = versions[0]
                    max_ver = versions[1]

                    if self._version_in_range(tech_version, min_ver, max_ver):
                        confidence = self._calculate_confidence(tech_version, min_ver, max_ver)
                        matches.append(CVEMatch(
                            cve=cve,
                            technology=technology,
                            matched_version=tech_version,
                            confidence=confidence,
                        ))

        return matches

    def _version_in_range(self, version_str: str, min_ver: str, max_ver: str) -> bool:
        """Check if version is in vulnerable range"""
        try:
            v = self._parse_version(version_str)
            min_v = self._parse_version(min_ver) if min_ver != "0" else None
            max_v = self._parse_version(max_ver) if max_ver != "0" else None

            if min_v and v < min_v:
                return False
            if max_v and v > max_v:
                return False
            return True
        except Exception:
            # If parsing fails, assume potentially vulnerable
            return True

    def _parse_version(self, version_str: str):
        """Simple version parser - converts version string to comparable tuple"""
        # Handle common version formats: 1.2.3, 1.2, v1.2.3, etc.
        import re
        # Remove non-numeric prefix (like 'v')
        clean = re.sub(r'^[^0-9]*', '', version_str)
        # Split by dots and convert to integers
        parts = []
        for part in clean.split('.'):
            # Extract leading digits
            match = re.match(r'(\d+)', part)
            if match:
                parts.append(int(match.group(1)))
            else:
                parts.append(0)
        # Pad to at least 3 parts
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _calculate_confidence(self, version_str: str, min_ver: str, max_ver: str) -> float:
        """Calculate confidence based on version proximity"""
        try:
            v = self._parse_version(version_str)
            min_v = self._parse_version(min_ver) if min_ver != "0" else None
            max_v = self._parse_version(max_ver) if max_ver != "0" else None

            if min_v and max_v:
                # Higher confidence if version is in middle of range
                range_size = tuple(b - a for a, b in zip(min_v, max_v))
                if range_size and any(x > 0 for x in range_size):
                    # Simple position calculation
                    position = 0.5  # Default to middle
                    return 0.7 + 0.2 * (1 - abs(position - 0.5) * 2)

            return 0.7
        except Exception:
            return 0.5

    def match_all(self, technologies: List[Technology]) -> List[CVEMatch]:
        """Match all technologies"""
        all_matches = []
        for tech in technologies:
            matches = self.match(tech)
            all_matches.extend(matches)
        return all_matches

    def to_vulnerabilities(self, matches: List[CVEMatch]) -> List[Vulnerability]:
        """Convert CVE matches to vulnerability objects"""
        vulns = []

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        for match in matches:
            vuln = Vulnerability(
                type=VulnerabilityType.OUTDATED_COMPONENTS,
                severity=severity_map.get(match.cve.severity.lower(), Severity.MEDIUM),
                title=f"{match.cve.cve_id}: {match.cve.title}",
                description=match.cve.description,
                location=f"{match.technology.name} {match.matched_version}",
                evidence="Detected version: " + match.matched_version + "\nCVE: " + match.cve.cve_id + "\nCVSS: " + str(match.cve.cvss_score),
                remediation=f"Upgrade {match.technology.name} to a non-vulnerable version",
                references=match.cve.references,
                cwe=match.cve.cwe,
                cvss=match.cve.cvss_vector,
                cvss_score=match.cve.cvss_score,
                tags=["cve", "outdated", match.cve.cve_id],
                scanner_module="cve_matcher",
                confidence=match.confidence,
            )
            vulns.append(vuln)

        return vulns

    def get_stats(self) -> Dict[str, Any]:
        """Get matcher statistics"""
        return {
            "total_cves": len(self.cve_db),
            "indexed_products": len(self._index),
            "by_severity": {},
        }
