"""
ZDay Scanner - Zero-Day Detection Engine
Async detector orchestration
"""
import asyncio
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from enum import Enum

from src.core.models import Target, Vulnerability, VulnerabilityType, Severity, Technology
from src.utils.http_client import HTTPClient, HTTPResponse


class DetectionPhase(Enum):
    """Detection phases"""
    PASSIVE = "passive"      # Passive analysis only
    ACTIVE = "active"        # Active probing
    INTRUSIVE = "intrusive"  # Potentially disruptive tests


@dataclass
class DetectionContext:
    """Context for detection"""
    target: Target
    http_client: HTTPClient
    technologies: List[Technology]
    custom_data: Dict[str, Any] = field(default_factory=dict)
    results: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class BaseDetector(ABC):
    """Base class for vulnerability detectors"""

    def __init__(self, config):
        self.config = config
        self.name = self.__class__.__name__
        self.enabled = True
        self.phase = DetectionPhase.ACTIVE
        self.vuln_types: List[VulnerabilityType] = []

    @abstractmethod
    async def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Run detection"""
        pass

    def _create_vuln(self, **kwargs) -> Vulnerability:
        """Helper to create vulnerability"""
        kwargs.setdefault('scanner_module', self.name)
        return Vulnerability(**kwargs)


class DetectionEngine:
    """Orchestrates multiple detectors"""

    def __init__(self, config):
        self.config = config
        self.detectors: List[BaseDetector] = []
        self._hooks: Dict[str, List[Callable]] = {
            'before_detect': [],
            'after_detect': [],
            'on_vuln': [],
        }

    def register(self, detector: BaseDetector):
        """Register a detector"""
        if detector.enabled:
            self.detectors.append(detector)

    def register_hook(self, event: str, callback: Callable):
        """Register event hook"""
        if event in self._hooks:
            self._hooks[event].append(callback)

    async def run(self, context: DetectionContext, phases: List[DetectionPhase] = None) -> List[Vulnerability]:
        """Run all detectors"""
        if phases is None:
            phases = [DetectionPhase.PASSIVE, DetectionPhase.ACTIVE, DetectionPhase.INTRUSIVE]

        all_vulns = []

        for phase in phases:
            phase_detectors = [d for d in self.detectors if d.phase == phase]

            # Run phase detectors concurrently
            tasks = []
            for detector in phase_detectors:
                # Call before hooks
                for hook in self._hooks['before_detect']:
                    await hook(detector, context)

                tasks.append(self._run_detector(detector, context))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for detector, result in zip(phase_detectors, results):
                    if isinstance(result, Exception):
                        context.errors.append(f"{detector.name}: {result}")
                    else:
                        all_vulns.extend(result)
                        context.results.extend(result)

                        # Call on_vuln hooks
                        for vuln in result:
                            for hook in self._hooks['on_vuln']:
                                await hook(vuln, context)

                        # Call after hooks
                        for hook in self._hooks['after_detect']:
                            await hook(detector, context, result)

        return all_vulns

    async def _run_detector(self, detector: BaseDetector, context: DetectionContext) -> List[Vulnerability]:
        """Run a single detector with error handling"""
        try:
            return await detector.detect(context)
        except Exception as e:
            context.errors.append(f"{detector.name} failed: {e}")
            return []

    def get_detectors_by_type(self, vuln_type: VulnerabilityType) -> List[BaseDetector]:
        """Get detectors for a specific vulnerability type"""
        return [d for d in self.detectors if vuln_type in d.vuln_types]

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            "total_detectors": len(self.detectors),
            "by_phase": {
                phase.value: len([d for d in self.detectors if d.phase == phase])
                for phase in DetectionPhase
            },
            "by_type": {
                vt.value: len(self.get_detectors_by_type(vt))
                for vt in VulnerabilityType
            },
        }
