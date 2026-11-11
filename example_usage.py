#!/usr/bin/env python3
"""
ZDay Scanner - Example Usage
Demonstrates programmatic API usage
"""
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "src"))

from core.models import Target
from core.config import ScannerConfig
from core.scanner import quick_scan, ZDayScanner
from reporting import JSONReporter, HTMLReporter, MarkdownReporter, ReportOptions


async def example_basic():
    """Basic scan with quick_scan helper"""
    print("=" * 50)
    print("Example 1: Basic Scan")
    print("=" * 50)

    result = await quick_scan("https://example.com")

    print(f"Scan ID: {result.scan_id}")
    print(f"Technologies: {len(result.technologies)}")
    for tech in result.technologies[:5]:
        print(f"  - {tech.name} ({tech.version or 'unknown'}) [{tech.category}]")

    print(f"Vulnerabilities: {len(result.vulnerabilities)}")
    for vuln in result.vulnerabilities[:5]:
        print(f"  - [{vuln.severity.value.upper()}] {vuln.title}")


async def example_custom_config():
    """Scan with custom configuration"""
    print("\n" + "=" * 50)
    print("Example 2: Custom Configuration")
    print("=" * 50)

    config = ScannerConfig(
        timeout=60,
        rate_limit=5.0,
        max_pages=50,
        crawl_depth=3,
        enable_headless_fingerprinting=False,
        enable_intrusive_tests=False,
        custom_headers={"User-Agent": "ZDay Scanner Example"},
    )

    target = Target(
        url="https://example.com",
        custom_headers={"X-Custom-Header": "test"},
    )

    async with ZDayScanner(config) as scanner:
        result = await scanner.scan(target, output_formats=["json", "html"])

    print(f"Reports generated: {list(result.reports.keys())}")


async def example_programmatic_reporting():
    """Generate reports programmatically"""
    print("\n" + "=" * 50)
    print("Example 3: Programmatic Reporting")
    print("=" * 50)

    # This would normally come from a scan
    from core.models import ScanResult, Technology, Vulnerability, VulnerabilityType, Severity

    result = ScanResult(
        target=Target(url="https://example.com"),
        scan_id="example123",
        technologies=[
            Technology(name="nginx", version="1.20.0", category="server", confidence=0.95),
            Technology(name="PHP", version="8.1.0", category="language", confidence=0.9),
        ],
        vulnerabilities=[
            Vulnerability(
                type=VulnerabilityType.XSS,
                severity=Severity.MEDIUM,
                title="Reflected XSS in Search",
                description="User input reflected without encoding",
                location="https://example.com/search?q=test",
                parameter="q",
                payload="<script>alert(1)</script>",
                evidence="Payload found in response body",
                remediation="Implement output encoding",
                cwe="CWE-79",
                cvss_score=6.1,
                scanner_module="injection_detector",
                confidence=0.85,
            )
        ],
    )

    options = ReportOptions(min_severity="low")

    # Generate all formats
    for reporter_class, name in [
        (JSONReporter, "JSON"),
        (HTMLReporter, "HTML"),
        (MarkdownReporter, "Markdown"),
    ]:
        reporter = reporter_class(options)
        output = reporter.generate(result)

        # Save to file
        filename = f"example_report_{name.lower()}{reporter.get_extension()}"
        with open(filename, 'w') as f:
            f.write(output)
        print(f"  Generated {filename}")


async def example_config_from_file():
    """Load configuration from YAML"""
    print("\n" + "=" * 50)
    print("Example 4: Config from File")
    print("=" * 50)

    import tempfile
    import yaml

    config_data = {
        "timeout": 45,
        "rate_limit": 3.0,
        "max_pages": 20,
        "enable_headless_fingerprinting": True,
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config_data, f)
        config_path = f.name

    try:
        config = ScannerConfig.from_yaml(config_path)
        print(f"Loaded config: timeout={config.timeout}, rate_limit={config.rate_limit}")
    finally:
        import os
        os.unlink(config_path)


async def example_environment_config():
    """Load configuration from environment variables"""
    print("\n" + "=" * 50)
    print("Example 5: Config from Environment")
    print("=" * 50)

    import os

    os.environ["ZDAY_TIMEOUT"] = "90"
    os.environ["ZDAY_RATE_LIMIT"] = "2.0"
    os.environ["ZDAY_ENABLE_HEADLESS_FINGERPRINTING"] = "true"

    try:
        config = ScannerConfig.from_env()
        print(f"Env config: timeout={config.timeout}, rate_limit={config.rate_limit}")
        print(f"Headless: {config.enable_headless_fingerprinting}")
    finally:
        for key in ["ZDAY_TIMEOUT", "ZDAY_RATE_LIMIT", "ZDAY_ENABLE_HEADLESS_FINGERPRINTING"]:
            os.environ.pop(key, None)


async def main():
    """Run all examples"""
    print("""
    ZDay Scanner - Example Usage
    """)

    await example_basic()
    await example_custom_config()
    await example_programmatic_reporting()
    await example_config_from_file()
    await example_environment_config()

    print("\n" + "=" * 50)
    print("All examples completed!")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
