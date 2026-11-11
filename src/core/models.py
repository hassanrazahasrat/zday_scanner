"""
ZDay Scanner - Core Data Models
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from uuid import uuid4


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


class VulnerabilityType(Enum):
    """Types of vulnerabilities"""
    # Injection
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "xss"
    SSTI = "ssti"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"

    # Deserialization
    DESERIALIZATION = "deserialization"

    # Authentication/Authorization
    AUTH_BYPASS = "auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_FIXATION = "session_fixation"

    # Logic
    BUSINESS_LOGIC = "business_logic"
    RACE_CONDITION = "race_condition"
    IDOR = "idor"

    # Crypto
    WEAK_CRYPTO = "weak_crypto"
    CERTIFICATE_ISSUES = "certificate_issues"

    # Configuration
    SECURITY_MISCONFIG = "security_misconfig"
    EXPOSED_SENSITIVE_FILES = "exposed_sensitive_files"
    INFORMATION_DISCLOSURE = "information_disclosure"

    # Client-side
    CSP_BYPASS = "csp_bypass"
    CLICKJACKING = "clickjacking"
    CSRF = "csrf"

    # Infrastructure
    OUTDATED_COMPONENTS = "outdated_components"
    WAF_BYPASS = "waf_bypass"





@dataclass
class Target:
    """Scan target"""
    url: str
    name: Optional[str] = None
    scope: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    auth: Optional[Dict[str, Any]] = None

    @property
    def domain(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).netloc



@dataclass
class Technology:
    """Detected technology"""
    name: str
    version: Optional[str] = None
    category: str = "unknown"  # cms, framework, server, language, waf, cloud, library
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    cpe: Optional[str] = None

    def __hash__(self):
        return hash((self.name, self.version, self.category))





@dataclass
class Fingerprint:
    """Fingerprint result"""
    technology: Technology
    matches: List[str] = field(default_factory=list)
    confidence: float = 0.0
    source: str = "unknown"  # http, tls, headless, js, cloud, waf, cms, framework
    metadata: Dict[str, Any] = field(default_factory=dict)





@dataclass
class Vulnerability:
    """Vulnerability finding"""
    id: str = field(default_factory=lambda: str(uuid4())[:8])
    type: VulnerabilityType = VulnerabilityType.INFORMATION_DISCLOSURE
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    location: str = ""
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    cvss: Optional[str] = None
    cvss_score: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)
    scanner_module: str = ""
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "cvss_score": self.cvss_score,
            "tags": self.tags,
            "discovered_at": self.discovered_at.isoformat(),
            "scanner_module": self.scanner_module,
            "confidence": self.confidence,
        }





@dataclass
class ScanResult:
    """Complete scan result"""
    # Required fields
    target: Target
    started_at: datetime

    # Optional fields with defaults
    scan_id: str = field(default_factory=lambda: str(uuid4())[:8])
    completed_at: Optional[datetime] = None
    duration: float = 0.0
    phases_completed: List[str] = field(default_factory=list)
    technologies: List[Technology] = field(default_factory=list)
    fingerprints: List[Fingerprint] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    pages_scanned: int = 0
    reports: Dict[str, Any] = field(default_factory=dict)

    # Properties for backward compatibility with scanner/reporters
    @property
    def start_time(self) -> datetime:
        """Alias for started_at"""
        return self.started_at

    @property
    def end_time(self) -> Optional[datetime]:
        """Alias for completed_at"""
        return self.completed_at

    @property
    def scan_info(self) -> Dict[str, Any]:
        """Scan info dict for reporters"""
        return {
            "target": str(self.target.url),
            "scan_id": self.scan_id,
            "start_time": self.started_at.isoformat() if self.started_at else None,
            "end_time": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.duration,
            "scanner_version": "1.0.0",
        }

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {}
        for v in self.vulnerabilities:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target.url,
            "scan_id": self.scan_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.duration,
            "phases_completed": self.phases_completed,
            "technologies": [
                {
                    "name": t.name,
                    "version": t.version,
                    "category": t.category,
                    "confidence": t.confidence,
                    "evidence": t.evidence,
                    "cpe": t.cpe,
                } for t in self.technologies
            ],
            "fingerprints": [
                {
                    "technology": f.technology.name,
                    "version": f.technology.version,
                    "category": f.technology.category,
                    "confidence": f.confidence,
                    "source": f.source,
                    "matches": f.matches,
                    "metadata": f.metadata,
                } for f in self.fingerprints
            ],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "errors": self.errors,
            "stats": self.stats,
            "severity_counts": self.severity_counts,
        }
