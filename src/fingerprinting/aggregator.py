"""
ZDay Scanner - Fingerprint Aggregator
Deduplication + confidence scoring
"""
from typing import List, Dict, Any, Set
from collections import defaultdict
from dataclasses import dataclass

from src.core.models import Fingerprint, Technology


@dataclass
class AggregatedFingerprint:
    """Aggregated fingerprint result"""
    technology: Technology
    sources: List[str]
    all_matches: List[str]
    final_confidence: float
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class FingerprintAggregator:
    """Aggregates and deduplicates fingerprints from multiple sources"""

    def __init__(self, min_confidence: float = 0.3):
        self.min_confidence = min_confidence

    def aggregate(self, fingerprints: List[Fingerprint]) -> List[AggregatedFingerprint]:
        """Aggregate fingerprints from all sources"""
        # Group by technology name + category
        groups = defaultdict(list)

        for fp in fingerprints:
            key = (fp.technology.name.lower(), fp.technology.category.lower())
            groups[key].append(fp)

        results = []

        for (name, category), fps in groups.items():
            # Merge all matches
            all_matches = []
            all_evidence = []
            sources = []
            max_confidence = 0.0
            versions = set()
            metadata = {}

            for fp in fps:
                all_matches.extend(fp.matches)
                all_evidence.extend(fp.technology.evidence)
                sources.append(fp.source)
                max_confidence = max(max_confidence, fp.confidence)

                if fp.technology.version:
                    versions.add(fp.technology.version)

                # Merge metadata
                for k, v in fp.metadata.items():
                    if k not in metadata:
                        metadata[k] = []
                    if isinstance(v, list):
                        metadata[k].extend(v)
                    else:
                        metadata[k].append(v)

            # Calculate final confidence
            # Boost confidence if multiple sources agree
            source_boost = min(len(set(sources)) * 0.1, 0.3)
            final_confidence = min(max_confidence + source_boost, 1.0)

            # Select best version (prefer more specific)
            version = None
            if versions:
                version = max(versions, key=len)

            # Create aggregated technology
            tech = Technology(
                name=fps[0].technology.name,  # Use first name as canonical
                version=version,
                category=fps[0].technology.category,
                confidence=final_confidence,
                evidence=list(set(all_evidence)),
                cpe=fps[0].technology.cpe,
            )

            agg = AggregatedFingerprint(
                technology=tech,
                sources=list(set(sources)),
                all_matches=list(set(all_matches)),
                final_confidence=final_confidence,
                metadata=metadata,
            )

            if final_confidence >= self.min_confidence:
                results.append(agg)

        # Sort by confidence descending
        results.sort(key=lambda x: x.final_confidence, reverse=True)

        return results

    def to_technologies(self, aggregated: List[AggregatedFingerprint]) -> List[Technology]:
        """Convert aggregated fingerprints to Technology list"""
        return [agg.technology for agg in aggregated]

    def get_summary(self, aggregated: List[AggregatedFingerprint]) -> Dict[str, Any]:
        """Get summary of aggregated results"""
        by_category = defaultdict(list)
        for agg in aggregated:
            by_category[agg.technology.category].append(agg)

        return {
            "total": len(aggregated),
            "by_category": {cat: len(items) for cat, items in by_category.items()},
            "high_confidence": len([a for a in aggregated if a.final_confidence >= 0.8]),
            "medium_confidence": len([a for a in aggregated if 0.5 <= a.final_confidence < 0.8]),
            "low_confidence": len([a for a in aggregated if a.final_confidence < 0.5]),
        }
