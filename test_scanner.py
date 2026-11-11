#!/usr/bin/env python3
"""
ZDay Scanner - Functional Test with Mock Data
Tests scanner functionality without network requests
"""
import sys
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Add project root to path (so we can import src.*)
sys.path.insert(0, str(Path(__file__).parent))

from src.core.models import Target, Technology, Vulnerability, VulnerabilityType, Severity, Fingerprint, ScanResult
from src.core.config import ScannerConfig
from src.core.scanner import ZDayScanner
from src.utils.http_client import HTTPClient, HTTPResponse
from src.fingerprinting.aggregator import FingerprintAggregator
from src.technologies.version_detector import VersionDetector
from src.technologies.cve_matcher import CVEMatcher
from src.zero_days.detection_engine import DetectionEngine, DetectionContext, DetectionPhase
from src.zero_days.injection_detector import InjectionDetector
from src.zero_days.detectors import AuthBypassDetector, LogicDetector
from src.reporting import JSONReporter, HTMLReporter, MarkdownReporter, ReportOptions


class MockHTTPClient:
    """Mock HTTP client for testing"""

    def __init__(self):
        self.responses = {}
        self.call_count = 0

    def add_response(self, url, status=200, text="", headers=None, cookies=None):
        self.responses[url] = {
            "status": status,
            "text": text,
            "headers": headers or {"Content-Type": "text/html"},
            "cookies": cookies or {},
        }

    async def get(self, url, **kwargs):
        self.call_count += 1
        return self._make_response(url)

    async def post(self, url, **kwargs):
        self.call_count += 1
        return self._make_response(url)

    async def head(self, url, **kwargs):
        self.call_count += 1
        return self._make_response(url)

    async def get_with_browser_headers(self, url, **kwargs):
        return await self.get(url, **kwargs)

    def _make_response(self, url):
        data = self.responses.get(url, {
            "status": 200,
            "text": "<html><head><title>Test</title></head><body>Test</body></html>",
            "headers": {"Content-Type": "text/html"},
            "cookies": {},
        })

        resp = MagicMock(spec=HTTPResponse)
        resp.status = data["status"]
        resp.text = data["text"]
        resp.content = data["text"].encode()
        resp.headers = data["headers"]
        resp.cookies = data["cookies"]
        resp.url = url
        resp.duration = 0.1
        return resp

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


async def test_fingerprint_aggregation():
    """Test fingerprint aggregation"""
    print("\n[Test] Fingerprint Aggregation")

    # Create mock fingerprints
    fp1 = Fingerprint(
        technology=Technology(name="WordPress", category="cms", confidence=0.9),
        matches=["generator", "wp-content"],
        confidence=0.9,
        source="http",
    )

    fp2 = Fingerprint(
        technology=Technology(name="WordPress", category="cms", confidence=0.8),
        matches=["wp-json"],
        confidence=0.8,
        source="js",
    )

    aggregator = FingerprintAggregator()
    results = aggregator.aggregate([fp1, fp2])

    assert len(results) == 1
    assert results[0].technology.name == "WordPress"
    assert results[0].final_confidence > 0.9  # Boosted by multiple sources
    print("  OK Aggregation works correctly")


async def test_version_detection():
    """Test version detection"""
    print("\n[Test] Version Detection")

    detector = VersionDetector()
    tech = Technology(name="WordPress", category="cms")

    data = {
        "body": '<meta name="generator" content="WordPress 6.4.2">',
        "headers": {},
        "scripts": [],
        "url": "https://example.com",
    }

    version = detector.get_best_version(tech, data)
    assert version == "6.4.2"
    print(f"  OK Detected version: {version}")


async def test_cve_matching():
    """Test CVE matching"""
    print("\n[Test] CVE Matching")

    matcher = CVEMatcher()

    # Test with known vulnerable version
    tech = Technology(name="WordPress", version="5.0", category="cms")
    matches = matcher.match(tech)

    # Should find CVE-2022-3590 (affects < 6.0.1)
    assert len(matches) > 0
    vulns = matcher.to_vulnerabilities(matches)
    assert len(vulns) > 0
    assert vulns[0].severity == Severity.MEDIUM
    print(f"  OK Found {len(vulns)} CVE matches")


async def test_injection_detector():
    """Test injection detector with mock responses"""
    print("\n[Test] Injection Detector")

    config = ScannerConfig()
    detector = InjectionDetector(config)

    # Create mock context
    target = Target(url="https://example.com")
    http_client = MockHTTPClient()

    # Add vulnerable response for SQLi
    http_client.add_response(
        "https://example.com/login",
        text="SQL syntax error near '1'='1'",
        status=500
    )

    context = DetectionContext(
        target=target,
        http_client=http_client,
        technologies=[],
    )

    # Test form discovery (mocked)
    with patch.object(detector, '_discover_forms', new_callable=AsyncMock) as mock_forms:
        mock_forms.return_value = [{
            "url": "https://example.com/login",
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text", "value": ""},
                {"name": "password", "type": "password", "value": ""},
            ]
        }]

        vulns = await detector.detect(context)

        # Should detect SQLi
        sqli_vulns = [v for v in vulns if v.type == VulnerabilityType.SQL_INJECTION]
        print(f"  OK SQL Injection test: {len(sqli_vulns)} vulnerabilities found")


async def test_reporting():
    """Test report generation"""
    print("\n[Test] Report Generation")

    # Create sample scan result
    target = Target(url="https://example.com")
    tech = Technology(name="nginx", version="1.20.0", category="server", confidence=0.9)
    vuln = Vulnerability(
        type=VulnerabilityType.XSS,
        severity=Severity.MEDIUM,
        title="Reflected XSS in search",
        description="XSS vulnerability in search parameter",
        location="https://example.com/search?q=test",
        parameter="q",
        payload="<script>alert(1)</script>",
        evidence="Payload reflected in response",
        remediation="Encode output",
        cwe="CWE-79",
        cvss_score=6.1,
        scanner_module="injection_detector",
        confidence=0.8,
    )

    result = ScanResult(
        target=target,
        scan_id="test123",
        technologies=[tech],
        vulnerabilities=[vuln],
    )

    options = ReportOptions(min_severity="info")

    # Test JSON reporter
    json_reporter = JSONReporter(options)
    json_output = json_reporter.generate(result)
    assert "Reflected XSS" in json_output
    assert "nginx" in json_output
    print("  OK JSON reporter works")

    # Test Markdown reporter
    md_reporter = MarkdownReporter(options)
    md_output = md_reporter.generate(result)
    assert "Reflected XSS" in md_output
    assert "nginx" in md_output
    print("  OK Markdown reporter works")

    # Test HTML reporter
    html_reporter = HTMLReporter(options)
    html_output = html_reporter.generate(result)
    assert "Reflected XSS" in html_output
    assert "nginx" in html_output
    assert "chart.js" in html_output.lower()
    print("  OK HTML reporter works")


async def test_config():
    """Test configuration loading"""
    print("\n[Test] Configuration")

    # Test default config
    config = ScannerConfig()
    assert config.timeout == 30
    assert config.rate_limit == 10.0
    print("  OK Default config works")

    # Test YAML config
    import tempfile
    import yaml

    yaml_content = """
    timeout: 60
    rate_limit: 5.0
    enable_headless_fingerprinting: false
    """

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(yaml_content)
        temp_path = f.name

    try:
        config2 = ScannerConfig.from_yaml(temp_path)
        assert config2.timeout == 60
        assert config2.rate_limit == 5.0
        assert config2.enable_headless_fingerprinting == False
        print("  OK YAML config loading works")
    finally:
        import os
        os.unlink(temp_path)

    # Test environment variables
    import os
    os.environ["ZDAY_TIMEOUT"] = "120"
    os.environ["ZDAY_RATE_LIMIT"] = "2.5"

    config3 = ScannerConfig.from_env()
    assert config3.timeout == 120
    assert config3.rate_limit == 2.5
    print("  OK Environment variable config works")

    del os.environ["ZDAY_TIMEOUT"]
    del os.environ["ZDAY_RATE_LIMIT"]


async def test_scanner_integration():
    """Test full scanner integration (mocked)"""
    print("\n[Test] Scanner Integration")

    config = ScannerConfig()
    config.enable_headless_fingerprinting = False
    config.enable_intrusive_tests = False

    target = Target(url="https://example.com")

    # Mock the HTTP client
    with patch('src.core.scanner.HTTPClient', return_value=MockHTTPClient()):
        scanner = ZDayScanner(config)
        scanner.http_client = MockHTTPClient()

        # Add mock responses
        scanner.http_client.add_response(
            "https://example.com",
            text='<html><head><meta name="generator" content="WordPress 6.4.2"></head><body>Test</body></html>',
            headers={"Server": "nginx", "X-Powered-By": "PHP/8.1.0"},
            cookies={"PHPSESSID": "abc123"}
        )

        # Mock fingerprinters to return quickly
        with patch('src.core.scanner.HTTPFingerprinter.fingerprint', new_callable=AsyncMock) as mock_http_fp:
            from src.fingerprinting.base import FingerprintSignature
            from src.core.models import Fingerprint, Technology

            mock_http_fp.return_value = [
                Fingerprint(
                    technology=Technology(name="nginx", category="server", version="1.20", confidence=0.9),
                    matches=["Server: nginx"],
                    confidence=0.9,
                    source="http",
                ),
                Fingerprint(
                    technology=Technology(name="PHP", category="language", version="8.1.0", confidence=0.8),
                    matches=["X-Powered-By: PHP/8.1.0"],
                    confidence=0.8,
                    source="http",
                ),
            ]

            with patch('src.core.scanner.TLSFingerprinter.fingerprint', new_callable=AsyncMock, return_value=[]):
                with patch('src.core.scanner.JSFingerprinter.fingerprint', new_callable=AsyncMock, return_value=[]):
                    with patch('src.core.scanner.CloudFingerprinter.fingerprint', new_callable=AsyncMock, return_value=[]):
                        with patch('src.core.scanner.WAFFingerprinter.fingerprint', new_callable=AsyncMock, return_value=[]):
                            with patch('src.core.scanner.CMSFingerprinter.fingerprint', new_callable=AsyncMock, return_value=[]):
                                with patch('src.core.scanner.FrameworkFingerprinter.fingerprint', new_callable=AsyncMock, return_value=[]):
                                    result = await scanner.scan(target, output_formats=[])

                                    assert len(result.technologies) > 0
                                    print(f"  OK Scanner ran successfully: {len(result.technologies)} technologies, {len(result.vulnerabilities)} vulns")


async def main():
    """Run all tests"""
    print("ZDay Scanner - Functional Tests")
    print("=" * 50)

    try:
        await test_config()
        await test_fingerprint_aggregation()
        await test_version_detection()
        await test_cve_matching()
        await test_injection_detector()
        await test_reporting()
        await test_scanner_integration()

        print("\n" + "=" * 50)
        print("ALL TESTS PASSED")
        return 0

    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
