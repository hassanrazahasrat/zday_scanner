#!/usr/bin/env python3
"""
ZDay Scanner - CLI Entry Point
Deep web application security scanner using Playwright
"""
import asyncio
import argparse
import sys
import os
from pathlib import Path
from typing import List, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core.models import Target, ScanResult
from src.core.config import ScannerConfig
from src.core.scanner import ZDayScanner
from src.reporting import JSONReporter, HTMLReporter, MarkdownReporter, ReportOptions


def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="ZDay Scanner - Deep web application security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m zday_scan -u https://example.com
  python -m zday_scan -u https://example.com -f json html -o ./reports
  python -m zday_scan -u https://example.com --depth 3 --max-pages 50
  python -m zday_scan -u https://example.com --browser-path auto
  python -m zday_scan -u https://example.com --cdp-endpoint http://localhost:9222
        """
    )

    # Target
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")

    # Scan options
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum pages to crawl (default: 100)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--rate-limit", type=float, default=10.0, help="Requests per second (default: 10)")
    parser.add_argument("--concurrency", type=int, default=10, help="Max concurrent requests (default: 10)")

    # Browser / Playwright options
    parser.add_argument("--no-headless", action="store_true", help="Disable headless browser fingerprinting")
    parser.add_argument("--browser-path", help="Browser executable path (default: auto-detect)")
    parser.add_argument("--browser-channel", choices=["chrome", "msedge", "chromium", "brave"],
                       help="Browser channel to use")
    parser.add_argument("--cdp-endpoint", help="Connect to existing browser via CDP (e.g., http://localhost:9222)")
    parser.add_argument("--browser-args", help="Comma-separated browser args")

    # Feature toggles
    parser.add_argument("--no-version-detection", action="store_true", help="Disable version detection")
    parser.add_argument("--no-cve-matching", action="store_true", help="Disable CVE matching")
    parser.add_argument("--no-injection-tests", action="store_true", help="Disable injection tests")
    parser.add_argument("--no-deserialization-tests", action="store_true", help="Disable deserialization tests")
    parser.add_argument("--no-auth-bypass-tests", action="store_true", help="Disable auth bypass tests")
    parser.add_argument("--no-logic-tests", action="store_true", help="Disable business logic tests")
    parser.add_argument("--no-race-condition-tests", action="store_true", help="Disable race condition tests")
    parser.add_argument("--no-crypto-tests", action="store_true", help="Disable crypto tests")
    parser.add_argument("--intrusive", action="store_true", help="Enable intrusive tests")

    # Authentication
    parser.add_argument("--auth-header", action="append", help="Custom auth header (can be used multiple times)")
    parser.add_argument("--cookie", action="append", help="Custom cookie (can be used multiple times)")

    # Proxy
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")

    # Output
    parser.add_argument("-f", "--format", action="append", 
                       choices=["json", "html", "markdown", "md"],
                       help="Output format (can be used multiple times)")
    parser.add_argument("-o", "--output-dir", help="Output directory for reports")
    parser.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"],
                       default="info", help="Minimum severity to report")

    # Config
    parser.add_argument("-c", "--config", help="Path to config YAML file")

    # Misc
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version="ZDay Scanner 1.0.0")

    return parser.parse_args()


def build_config(args: argparse.Namespace) -> ScannerConfig:
    """Build scanner config from arguments"""
    # Start with file config if provided
    if args.config:
        config = ScannerConfig.from_yaml(args.config)
    else:
        config = ScannerConfig()

    # Override with CLI args
    config.timeout = args.timeout
    config.rate_limit = args.rate_limit
    config.max_concurrent = args.concurrency
    config.max_pages = args.max_pages
    config.crawl_depth = args.depth

    config.enable_headless_fingerprinting = not args.no_headless
    config.enable_version_detection = not args.no_version_detection
    config.enable_cve_matching = not args.no_cve_matching
    config.enable_injection_tests = not args.no_injection_tests
    config.enable_deserialization_tests = not args.no_deserialization_tests
    config.enable_auth_bypass_tests = not args.no_auth_bypass_tests
    config.enable_logic_tests = not args.no_logic_tests
    config.enable_race_condition_tests = not args.no_race_condition_tests
    config.enable_crypto_tests = not args.no_crypto_tests
    config.enable_intrusive_tests = args.intrusive

    config.verify_ssl = True
    config.follow_redirects = True

    # Browser settings
    if args.browser_path:
        config.browser_executable_path = args.browser_path
    if args.browser_channel:
        config.browser_channel = args.browser_channel
    if args.cdp_endpoint:
        config.cdp_endpoint = args.cdp_endpoint
    if args.browser_args:
        config.browser_args = [a.strip() for a in args.browser_args.split(",")]

    # Auth headers
    if args.auth_header:
        for h in args.auth_header:
            if ":" in h:
                k, v = h.split(":", 1)
                config.custom_headers[k.strip()] = v.strip()

    # Cookies
    if args.cookie:
        for c in args.cookie:
            if "=" in c:
                k, v = c.split("=", 1)
                config.custom_cookies[k.strip()] = v.strip()

    # Proxy
    if args.proxy:
        config.proxy = args.proxy

    return config


def print_summary(result: ScanResult):
    """Print scan summary"""
    print("\n" + "="*60)
    print("SCAN COMPLETE")
    print("="*60)
    print(f"Scan ID: {result.scan_id if hasattr(result, 'scan_id') else 'N/A'}")
    print(f"Duration: {result.duration:.2f}s")
    print(f"Technologies: {len(result.technologies)}")
    print(f"Fingerprints: {len(result.fingerprints)}")

    # Count by severity
    by_sev = {}
    for fp in result.fingerprints:
        # Map confidence to severity-ish
        if fp.confidence >= 0.9:
            sev = "high"
        elif fp.confidence >= 0.7:
            sev = "medium"
        elif fp.confidence >= 0.5:
            sev = "low"
        else:
            sev = "info"
        by_sev[sev] = by_sev.get(sev, 0) + 1

    for sev in ["high", "medium", "low", "info"]:
        if by_sev.get(sev, 0) > 0:
            print(f"  {sev.title()}: {by_sev[sev]}")

    if result.errors:
        print(f"\nErrors: {len(result.errors)}")
        for err in result.errors[:5]:
            print(f"  - {err}")

    if result.reports:
        print("\nReports generated:")
        for fmt, path in result.reports.items():
            if os.path.exists(path):
                print(f"  {fmt.upper()}: {path}")
            else:
                print(f"  {fmt.upper()}: (embedded)")


async def main():
    """Main entry point"""
    args = parse_args()

    # Build config
    config = build_config(args)

    # Parse output formats
    output_formats = args.format or ["html"]
    # Normalize markdown alias
    output_formats = ["markdown" if f == "md" else f for f in output_formats]

    # Create target
    target = Target(
        url=args.url,
        headers=config.custom_headers,
        cookies=config.custom_cookies,
    )

    # Print banner
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║  ZDay Scanner v1.0.0                                        ║
    ║  Deep Web Application Security Scanner                      ║
    ║  Powered by Playwright                                       ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

    print(f"[*] Target: {args.url}")
    print(f"[*] Depth: {args.depth} | Max Pages: {args.max_pages} | Rate: {args.rate_limit}/s")
    print(f"[*] Headless: {'Enabled' if config.enable_headless_fingerprinting else 'Disabled'}")
    if config.browser_executable_path:
        print(f"[*] Browser: {config.browser_executable_path}")
    if config.browser_channel:
        print(f"[*] Channel: {config.browser_channel}")
    if config.cdp_endpoint:
        print(f"[*] CDP: {config.cdp_endpoint}")
    print(f"[*] Formats: {', '.join(output_formats)}")
    if args.output_dir:
        print(f"[*] Output: {args.output_dir}")
    print()

    # Run scan
    try:
        async with ZDayScanner(config) as scanner:
            result = await scanner.scan(target, output_formats, args.output_dir)

        print_summary(result)

        # Exit code based on findings (high confidence = potential issues)
        high_conf = sum(1 for fp in result.fingerprints if fp.confidence >= 0.9)
        if high_conf > 10:
            sys.exit(1)
        else:
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
