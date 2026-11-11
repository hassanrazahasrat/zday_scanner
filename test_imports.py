#!/usr/bin/env python3
"""
ZDay Scanner - Import Verification Script
Tests that all modules can be imported without errors
"""
import sys
import traceback
from pathlib import Path

# Add project root to path (so we can import src.*)
sys.path.insert(0, str(Path(__file__).parent))

def test_import(module_name, description=""):
    """Test importing a module"""
    try:
        __import__(module_name)
        print(f"  OK {module_name} {description}")
        return True
    except Exception as e:
        print(f"  FAIL {module_name} {description}")
        print(f"    Error: {e}")
        return False

def main():
    print("ZDay Scanner - Import Verification")
    print("=" * 50)

    all_passed = True

    # Core modules
    print("\n[Core Modules]")
    all_passed &= test_import("src.core.models", "- Data models")
    all_passed &= test_import("src.core.config", "- Configuration")
    all_passed &= test_import("src.core.scanner", "- Main scanner")

    # Utils
    print("\n[Utils]")
    all_passed &= test_import("src.utils.http_client", "- HTTP client")

    # Fingerprinting
    print("\n[Fingerprinting]")
    all_passed &= test_import("src.fingerprinting.base", "- Base fingerprinter")
    all_passed &= test_import("src.fingerprinting.http_fingerprinter", "- HTTP fingerprinter")
    all_passed &= test_import("src.fingerprinting.tls_fingerprinter", "- TLS fingerprinter")
    all_passed &= test_import("src.fingerprinting.headless_browser", "- Headless browser")
    all_passed &= test_import("src.fingerprinting.js_fingerprinter", "- JS fingerprinter")
    all_passed &= test_import("src.fingerprinting.cloud_fingerprinter", "- Cloud fingerprinter")
    all_passed &= test_import("src.fingerprinting.waf_fingerprinter", "- WAF fingerprinter")
    all_passed &= test_import("src.fingerprinting.cms_fingerprinter", "- CMS fingerprinter")
    all_passed &= test_import("src.fingerprinting.framework_fingerprinter", "- Framework fingerprinter")
    all_passed &= test_import("src.fingerprinting.aggregator", "- Fingerprint aggregator")

    # Technologies
    print("\n[Technologies]")
    all_passed &= test_import("src.technologies.fingerprint_db", "- Fingerprint database")
    all_passed &= test_import("src.technologies.version_detector", "- Version detector")
    all_passed &= test_import("src.technologies.cve_matcher", "- CVE matcher")

    # Zero Days
    print("\n[Zero-Day Detection]")
    all_passed &= test_import("src.zero_days.detection_engine", "- Detection engine")
    all_passed &= test_import("src.zero_days.injection_detector", "- Injection detector")
    all_passed &= test_import("src.zero_days.detectors", "- Additional detectors")

    # Reporting
    print("\n[Reporting]")
    all_passed &= test_import("src.reporting.base", "- Base reporter")
    all_passed &= test_import("src.reporting.json_reporter", "- JSON reporter")
    all_passed &= test_import("src.reporting.html_reporter", "- HTML reporter")
    all_passed &= test_import("src.reporting.markdown_reporter", "- Markdown reporter")

    # Package imports
    print("\n[Package Imports]")
    all_passed &= test_import("src", "- src package")

    print("\n" + "=" * 50)
    if all_passed:
        print("ALL IMPORTS PASSED")
        return 0
    else:
        print("SOME IMPORTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
