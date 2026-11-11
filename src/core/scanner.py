"""
ZDay Scanner - Main Scanner Orchestration
4-phase pipeline: Recon → Fingerprint → Vuln Detection → Reporting
"""
import asyncio
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from src.core.models import Target, ScanResult, Technology, Vulnerability, Fingerprint
from src.core.config import ScannerConfig
from src.utils.http_client import HTTPClient
from src.fingerprinting import (
    HTTPFingerprinter, TLSFingerprinter, HeadlessBrowserFingerprinter,
    JSFingerprinter, CloudFingerprinter, WAFFingerprinter,
    CMSFingerprinter, FrameworkFingerprinter, FingerprintAggregator
)
from src.technologies import VersionDetector, CVEMatcher
from src.zero_days import (
    DetectionEngine, InjectionDetector, DeserializationDetector,
    AuthBypassDetector, LogicDetector, RaceConditionDetector, CryptoDetector
)
from src.reporting import JSONReporter, HTMLReporter, MarkdownReporter, ReportOptions


@dataclass
class ScanContext:
    """Context for a running scan"""
    target: Target
    config: ScannerConfig
    http_client: HTTPClient
    start_time: datetime = field(default_factory=datetime.utcnow)
    technologies: List[Technology] = field(default_factory=list)
    fingerprints: List[Fingerprint] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class ZDayScanner:
    """Main scanner class orchestrating all phases"""

    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.http_client = None

    async def __aenter__(self):
        self.http_client = HTTPClient(self.config)
        await self.http_client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.http_client:
            await self.http_client.__aexit__(exc_type, exc_val, exc_tb)

    async def scan(self, target: Target, 
                   output_formats: List[str] = None,
                   output_dir: str = None) -> ScanResult:
        """Run full scan pipeline"""

        scan_id = str(uuid.uuid4())[:8]
        context = ScanContext(target=target, config=self.config, http_client=self.http_client)

        try:
            # Phase 1: Reconnaissance
            await self._phase_recon(context)

            # Phase 2: Fingerprinting
            await self._phase_fingerprint(context)

            # Phase 3: Vulnerability Detection
            await self._phase_vuln_detection(context)

            # Phase 4: Reporting
            result = await self._phase_reporting(context, scan_id, output_formats, output_dir)

            return result

        except Exception as e:
            context.errors.append(f"Scan failed: {e}")
            # Return partial result
            return ScanResult(
                target=target,
                scan_id=scan_id,
                started_at=context.start_time,
                completed_at=datetime.utcnow(),
                technologies=context.technologies,
                vulnerabilities=context.vulnerabilities,
                errors=context.errors,
            )

    async def _phase_recon(self, context: ScanContext):
        """Phase 1: Reconnaissance - Discover endpoints, forms, etc."""
        # The HTTP client already does basic recon during fingerprinting
        # This phase can be extended for subdomain enumeration, directory brute-forcing, etc.
        pass

    async def _phase_fingerprint(self, context: ScanContext):
        """Phase 2: Fingerprinting - Identify technologies"""
        # Initialize all fingerprinters
        fingerprinters = [
            HTTPFingerprinter(self.config),
            TLSFingerprinter(self.config),
            JSFingerprinter(self.config),
            CloudFingerprinter(self.config),
            WAFFingerprinter(self.config),
            CMSFingerprinter(self.config),
            FrameworkFingerprinter(self.config),
        ]

        # Add headless if enabled
        if self.config.enable_headless_fingerprinting:
            fingerprinters.append(HeadlessBrowserFingerprinter(self.config))

        # Run all fingerprinters concurrently
        tasks = [fp.fingerprint(context.target, context.http_client) for fp in fingerprinters]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_fingerprints = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                context.errors.append(f"Fingerprinter {fingerprinters[i].__class__.__name__} failed: {result}")
            else:
                all_fingerprints.extend(result)

        context.fingerprints = all_fingerprints

        # Aggregate and deduplicate
        aggregator = FingerprintAggregator(min_confidence=0.3)
        aggregated = aggregator.aggregate(all_fingerprints)
        context.technologies = aggregator.to_technologies(aggregated)

        # Enrich with version detection
        if self.config.enable_version_detection:
            version_detector = VersionDetector()
            # Collect data for version detection
            try:
                resp = await context.http_client.get_with_browser_headers(context.target.url)
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")

                meta_tags = {}
                for meta in soup.find_all("meta"):
                    name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
                    content = meta.get("content", "")
                    if name:
                        meta_tags[name.lower()] = content

                scripts = []
                for script in soup.find_all("script"):
                    src = script.get("src", "")
                    content = script.string or ""
                    if src:
                        scripts.append(src)
                    if content:
                        scripts.append(content[:10000])

                data = {
                    "url": str(resp.url),
                    "headers": {k.lower(): v for k, v in resp.headers.items()},
                    "cookies": resp.cookies,
                    "meta_tags": meta_tags,
                    "scripts": scripts,
                    "body": resp.text,
                }

                context.technologies = version_detector.enrich_technologies(context.technologies, data)
            except Exception:
                pass

        # Match CVEs
        if self.config.enable_cve_matching:
            cve_matcher = CVEMatcher()
            cve_matches = cve_matcher.match_all(context.technologies)
            cve_vulns = cve_matcher.to_vulnerabilities(cve_matches)
            context.vulnerabilities.extend(cve_vulns)

    async def _phase_vuln_detection(self, context: ScanContext):
        """Phase 3: Vulnerability Detection - Zero-day detection"""
        # Initialize detection engine
        engine = DetectionEngine(self.config)

        # Register detectors based on config
        if self.config.enable_injection_tests:
            engine.register(InjectionDetector(self.config))

        if self.config.enable_deserialization_tests:
            engine.register(DeserializationDetector(self.config))

        if self.config.enable_auth_bypass_tests:
            engine.register(AuthBypassDetector(self.config))

        if self.config.enable_logic_tests:
            engine.register(LogicDetector(self.config))

        if self.config.enable_race_condition_tests:
            engine.register(RaceConditionDetector(self.config))

        if self.config.enable_crypto_tests:
            engine.register(CryptoDetector(self.config))

        # Create detection context
        det_context = context.target
        det_context = context  # Use our ScanContext which has more fields

        # Run detection
        phases = [engine.DetectionPhase.PASSIVE, engine.DetectionPhase.ACTIVE]
        if self.config.enable_intrusive_tests:
            phases.append(engine.DetectionPhase.INTRUSIVE)

        vulns = await engine.run(det_context, phases)
        context.vulnerabilities.extend(vulns)

    async def _phase_reporting(self, context: ScanContext, scan_id: str,
                               output_formats: List[str], output_dir: str) -> ScanResult:
        """Phase 4: Reporting"""
        end_time = datetime.utcnow()

        # Create scan result
        result = ScanResult(
            target=context.target,
            scan_id=scan_id,
            started_at=context.start_time,
            end_time=end_time,
            technologies=context.technologies,
            vulnerabilities=context.vulnerabilities,
            errors=context.errors,
        )

        # Generate reports
        if output_formats:
            options = ReportOptions(
                include_technologies=True,
                include_vulnerabilities=True,
                include_evidence=True,
                include_remediation=True,
                min_severity="info",
            )

            reporters = {
                "json": JSONReporter(options),
                "html": HTMLReporter(options),
                "markdown": MarkdownReporter(options),
            }

            for fmt in output_formats:
                if fmt in reporters:
                    try:
                        report_content = reporters[fmt].generate(result)
                        ext = reporters[fmt].get_extension()

                        if output_dir:
                            import os
                            os.makedirs(output_dir, exist_ok=True)
                            filename = f"zday_report_{scan_id}{ext}"
                            filepath = os.path.join(output_dir, filename)
                            with open(filepath, 'w') as f:
                                f.write(report_content)
                            result.reports[fmt] = filepath
                        else:
                            result.reports[fmt] = report_content
                    except Exception as e:
                        context.errors.append(f"Report generation ({fmt}) failed: {e}")

        return result


async def quick_scan(url: str, config: ScannerConfig = None, 
                     output_formats: List[str] = None) -> ScanResult:
    """Convenience function for quick scans"""
    target = Target(url=url)

    if config is None:
        config = ScannerConfig()

    async with ZDayScanner(config) as scanner:
        return await scanner.scan(target, output_formats)
