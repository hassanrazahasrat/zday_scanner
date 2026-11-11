"""
ZDay Scanner - Main Package
"""
__version__ = "1.0.0"
__author__ = "ZDay Scanner Team"

# Make core modules available at package level
from .core.models import (
    Target,
    Technology,
    Fingerprint,
    Vulnerability,
    ScanResult,
    Severity,
    VulnerabilityType,
)

from .core.config import ScannerConfig
from .core.scanner import ZDayScanner, quick_scan

from .reporting import (
    JSONReporter,
    HTMLReporter,
    MarkdownReporter,
    ReportOptions,
)

__all__ = [
    "Target",
    "Technology",
    "Fingerprint",
    "Vulnerability",
    "ScanResult",
    "Severity",
    "VulnerabilityType",
    "ScannerConfig",
    "ZDayScanner",
    "quick_scan",
    "JSONReporter",
    "HTMLReporter",
    "MarkdownReporter",
    "ReportOptions",
]
