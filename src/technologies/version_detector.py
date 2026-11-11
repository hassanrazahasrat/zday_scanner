"""
ZDay Scanner - Version Detector
Extracts version numbers from various sources
"""
import re
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

from src.core.models import Technology


@dataclass
class VersionMatch:
    """A version match with source info"""
    version: str
    source: str
    confidence: float
    evidence: str


class VersionDetector:
    """Detects and extracts version numbers for technologies"""

    # Common version patterns
    VERSION_PATTERNS = [
        # Semantic versioning
        (re.compile(r'(\d+\.\d+\.\d+(?:-[\w.]+)?(?:\+[\w.]+)?)'), 0.9),
        # Two-part version
        (re.compile(r'(\d+\.\d+(?:-[\w.]+)?)'), 0.7),
        # v prefix
        (re.compile(r'v(\d+\.\d+\.\d+(?:-[\w.]+)?)'), 0.85),
        # Version in URL path
        (re.compile(r'/v(\d+\.\d+\.\d+)/'), 0.8),
        # Package version
        (re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+)"'), 0.9),
    ]

    # Technology-specific version extractors
    TECH_EXTRACTORS = {
        "WordPress": [
            (re.compile(r'wp-includes/js/wp-emoji-release\.min\.js\?ver=(\d+\.\d+\.\d+)'), 0.95),
            (re.compile(r'WordPress\s+(\d+\.\d+\.\d+)'), 0.9),
            (re.compile(r'content="WordPress\s+(\d+\.\d+\.\d+)"'), 0.95),
        ],
        "Drupal": [
            (re.compile(r'Drupal\s+(\d+\.\d+)'), 0.9),
            (re.compile(r'content="Drupal\s+(\d+\.\d+)"'), 0.95),
        ],
        "Joomla": [
            (re.compile(r'Joomla!\s+(\d+\.\d+\.\d+)'), 0.9),
            (re.compile(r'Joomla\s+(\d+\.\d+\.\d+)'), 0.9),
        ],
        "Magento": [
            (re.compile(r'Magento/(\d+\.\d+\.\d+)'), 0.95),
            (re.compile(r'Magento\s+(\d+\.\d+\.\d+)'), 0.9),
        ],
        "React": [
            (re.compile(r'react[.-](\d+\.\d+\.\d+)'), 0.9),
            (re.compile(r'"react"\s*:\s*"(\d+\.\d+\.\d+)"'), 0.95),
        ],
        "Vue.js": [
            (re.compile(r'vue[.-](\d+\.\d+\.\d+)'), 0.9),
            (re.compile(r'"vue"\s*:\s*"(\d+\.\d+\.\d+)"'), 0.95),
        ],
        "Angular": [
            (re.compile(r'angular[.-](\d+\.\d+\.\d+)'), 0.9),
            (re.compile(r'@angular/core[.-](\d+\.\d+\.\d+)'), 0.95),
        ],
        "jQuery": [
            (re.compile(r'jquery[.-](\d+\.\d+\.\d+)'), 0.95),
            (re.compile(r'jQuery\s+v?(\d+\.\d+\.\d+)'), 0.9),
        ],
        "Bootstrap": [
            (re.compile(r'bootstrap[.-](\d+\.\d+\.\d+)'), 0.9),
            (re.compile(r'Bootstrap\s+v?(\d+\.\d+\.\d+)'), 0.85),
        ],
        "nginx": [
            (re.compile(r'nginx/(\d+\.\d+\.\d+)'), 0.95),
        ],
        "Apache": [
            (re.compile(r'Apache/(\d+\.\d+\.\d+)'), 0.95),
        ],
        "PHP": [
            (re.compile(r'PHP/(\d+\.\d+\.\d+)'), 0.95),
            (re.compile(r'X-Powered-By:\s*PHP/(\d+\.\d+\.\d+)'), 0.95),
        ],
        "Node.js": [
            (re.compile(r'node[.-](\d+\.\d+\.\d+)'), 0.8),
        ],
        "Python": [
            (re.compile(r'Python/(\d+\.\d+\.\d+)'), 0.9),
        ],
    }

    def __init__(self):
        self.cache: Dict[str, List[VersionMatch]] = {}

    def detect_versions(self, technology: Technology, data: Dict[str, Any]) -> List[VersionMatch]:
        """Detect versions for a technology from collected data"""
        matches = []

        # Get technology-specific extractors
        extractors = self.TECH_EXTRACTORS.get(technology.name, [])

        # Collect all text sources
        texts = []
        texts.append(("body", data.get("body", "")))
        texts.append(("url", data.get("url", "")))

        for header, value in data.get("headers", {}).items():
            texts.append((f"header:{header}", value))

        for cookie, value in data.get("cookies", {}).items():
            texts.append((f"cookie:{cookie}", value))

        for script in data.get("scripts", []):
            texts.append(("script", script))

        # Try technology-specific extractors first
        for pattern, confidence in extractors:
            for source_name, text in texts:
                match = pattern.search(text)
                if match:
                    version = match.group(1) if match.groups() else match.group(0)
                    if self._is_valid_version(version):
                        matches.append(VersionMatch(
                            version=version,
                            source=source_name,
                            confidence=confidence,
                            evidence=match.group(0)[:200],
                        ))

        # Try generic patterns
        for pattern, confidence in self.VERSION_PATTERNS:
            for source_name, text in texts:
                for match in pattern.finditer(text):
                    version = match.group(1) if match.groups() else match.group(0)
                    if self._is_valid_version(version) and self._is_likely_version(technology.name, version):
                        matches.append(VersionMatch(
                            version=version,
                            source=source_name,
                            confidence=confidence * 0.7,  # Lower confidence for generic
                            evidence=match.group(0)[:200],
                        ))

        # Deduplicate and sort by confidence
        return self._deduplicate(matches)

    def _is_valid_version(self, version: str) -> bool:
        """Check if string looks like a valid version"""
        # Must have at least major.minor
        parts = version.split('.')
        if len(parts) < 2:
            return False

        # Each part should be numeric (or start with numeric)
        for part in parts[:3]:  # Check first 3 parts
            if not part[0].isdigit():
                return False

        # Not too long
        if len(version) > 20:
            return False

        # Not a year-like number
        if len(parts) == 1 and len(parts[0]) == 4 and parts[0].startswith('20'):
            return False

        return True

    def _is_likely_version(self, tech_name: str, version: str) -> bool:
        """Check if version is likely for this technology"""
        # Skip versions that look like dates
        if re.match(r'^20\d{2}\.\d{2}', version):
            return False

        # Skip very high version numbers (likely false positives)
        parts = version.split('.')
        if parts and parts[0].isdigit() and int(parts[0]) > 100:
            return False

        return True

    def _deduplicate(self, matches: List[VersionMatch]) -> List[VersionMatch]:
        """Remove duplicate versions, keep highest confidence"""
        seen: Dict[str, VersionMatch] = {}

        for match in matches:
            key = match.version
            if key not in seen or match.confidence > seen[key].confidence:
                seen[key] = match

        # Sort by confidence descending
        result = list(seen.values())
        result.sort(key=lambda x: x.confidence, reverse=True)

        return result

    def get_best_version(self, technology: Technology, data: Dict[str, Any]) -> Optional[str]:
        """Get the best version match for a technology"""
        matches = self.detect_versions(technology, data)
        if matches:
            return matches[0].version
        return None

    def enrich_technologies(self, technologies: List[Technology], data: Dict[str, Any]) -> List[Technology]:
        """Enrich technologies with detected versions"""
        enriched = []
        for tech in technologies:
            version = self.get_best_version(tech, data)
            if version and version != tech.version:
                # Create new technology with updated version
                enriched_tech = Technology(
                    name=tech.name,
                    version=version,
                    category=tech.category,
                    confidence=tech.confidence,
                    evidence=tech.evidence + [f"Version detected: {version}"],
                    cpe=tech.cpe,
                )
                enriched.append(enriched_tech)
            else:
                enriched.append(tech)
        return enriched
