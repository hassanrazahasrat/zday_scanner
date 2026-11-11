"""
ZDay Scanner - Base Fingerprinter Classes
"""
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Pattern, Set
from collections import defaultdict

from src.core.models import Technology, Fingerprint


@dataclass
class FingerprintSignature:
    """A single fingerprint signature"""
    name: str
    version: Optional[str] = None
    category: str = "unknown"
    patterns: List[Pattern] = field(default_factory=list)
    headers: Dict[str, Pattern] = field(default_factory=dict)
    cookies: Dict[str, Pattern] = field(default_factory=dict)
    meta_tags: Dict[str, Pattern] = field(default_factory=dict)
    scripts: List[Pattern] = field(default_factory=list)
    body_patterns: List[Pattern] = field(default_factory=list)
    url_patterns: List[Pattern] = field(default_factory=list)
    cpe: Optional[str] = None
    confidence_base: float = 0.7
    version_extractors: List[Pattern] = field(default_factory=list)

    def __post_init__(self):
        # Compile string patterns to regex
        for key, value in list(self.headers.items()):
            if isinstance(value, str):
                self.headers[key] = re.compile(value, re.IGNORECASE)
        for key, value in list(self.cookies.items()):
            if isinstance(value, str):
                self.cookies[key] = re.compile(value, re.IGNORECASE)
        for key, value in list(self.meta_tags.items()):
            if isinstance(value, str):
                self.meta_tags[key] = re.compile(value, re.IGNORECASE)


class FingerprinterBase(ABC):
    """Abstract base class for all fingerprinters"""

    def __init__(self, config):
        self.config = config
        self.signatures: List[FingerprintSignature] = []
        import logging
        self.logger = logging.getLogger(self.__class__.__name__)
        self._load_signatures()

    @abstractmethod
    def _load_signatures(self):
        """Load fingerprint signatures"""
        pass

    @abstractmethod
    async def fingerprint(self, target, http_client) -> List[Fingerprint]:
        """Perform fingerprinting"""
        pass

    def _match_signature(self, sig: FingerprintSignature, data: Dict[str, Any]) -> Optional[Fingerprint]:
        """Match a signature against collected data"""
        matches = []
        confidence = 0.0

        # Check headers (case-insensitive)
        headers_data = data.get("headers", {})
        for header, pattern in sig.headers.items():
            # Try exact match first, then case-insensitive
            header_val = headers_data.get(header, "")
            if not header_val:
                # Case-insensitive lookup
                for k, v in headers_data.items():
                    if k.lower() == header.lower():
                        header_val = v
                        break
            if pattern.search(header_val):
                matches.append(f"header:{header}")
                confidence += 0.3

        # Check cookies
        for cookie, pattern in sig.cookies.items():
            cookie_val = data.get("cookies", {}).get(cookie, "")
            if pattern.search(cookie_val):
                matches.append(f"cookie:{cookie}")
                confidence += 0.2

        # Check meta tags
        for meta, pattern in sig.meta_tags.items():
            meta_val = data.get("meta_tags", {}).get(meta, "")
            if pattern.search(meta_val):
                matches.append(f"meta:{meta}")
                confidence += 0.25

        # Check scripts
        for pattern in sig.scripts:
            for script in data.get("scripts", []):
                if pattern.search(script):
                    matches.append(f"script:{pattern.pattern[:50]}")
                    confidence += 0.2
                    break

        # Check body patterns
        for pattern in sig.body_patterns:
            if pattern.search(data.get("body", "")):
                matches.append(f"body:{pattern.pattern[:50]}")
                confidence += 0.15

        # Check URL patterns
        for pattern in sig.url_patterns:
            if pattern.search(data.get("url", "")):
                matches.append(f"url:{pattern.pattern[:50]}")
                confidence += 0.2

        if matches:
            # Extract version if available
            version = sig.version
            if not version and sig.version_extractors:
                for extractor in sig.version_extractors:
                    for text in [data.get("body", "")] + list(data.get("headers", {}).values()):
                        match = extractor.search(text)
                        if match:
                            version = match.group(1) if match.groups() else match.group(0)
                            break

            tech = Technology(
                name=sig.name,
                version=version,
                category=sig.category,
                confidence=min(confidence, 1.0),
                evidence=matches,
                cpe=sig.cpe,
            )

            return Fingerprint(
                technology=tech,
                matches=matches,
                confidence=min(confidence, 1.0),
                source=self.__class__.__name__.replace("Fingerprinter", "").lower(),
            )

        return None


class FingerprinterRegistry:
    """Registry for all fingerprinters"""

    _fingerprinters: Dict[str, type] = {}
    _instances: Dict[str, FingerprinterBase] = {}

    @classmethod
    def register(cls, name: str, fingerprinter_class: type):
        """Register a fingerprinter class"""
        cls._fingerprinters[name] = fingerprinter_class

    @classmethod
    def get(cls, name: str, config) -> Optional[FingerprinterBase]:
        """Get fingerprinter instance"""
        if name not in cls._instances:
            if name in cls._fingerprinters:
                cls._instances[name] = cls._fingerprinters[name](config)
            else:
                return None
        return cls._instances[name]

    @classmethod
    def get_all(cls, config, enabled: List[str] = None) -> List[FingerprinterBase]:
        """Get all enabled fingerprinters"""
        if enabled is None:
            enabled = list(cls._fingerprinters.keys())

        result = []
        for name in enabled:
            fp = cls.get(name, config)
            if fp:
                result.append(fp)
        return result

    @classmethod
    def list_available(cls) -> List[str]:
        """List all registered fingerprinters"""
        return list(cls._fingerprinters.keys())


def register_fingerprinter(name: str):
    """Decorator to register a fingerprinter"""
    def decorator(cls):
        FingerprinterRegistry.register(name, cls)
        return cls
    return decorator
