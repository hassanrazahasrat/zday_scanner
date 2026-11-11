"""
ZDay Scanner - JavaScript Framework Fingerprinter
"""
import re
from typing import List

from src.fingerprinting.base import FingerprinterBase, FingerprintSignature


class JSFingerprinter(FingerprinterBase):
    """Fingerprints JavaScript frameworks and libraries"""

    name = "js_fingerprinter"

    def __init__(self, config):
        super().__init__(config)
        # signatures will be loaded by _load_signatures

    def _load_signatures(self):
        """Load fingerprint signatures"""
        self.signatures = self._build_signatures()

    def _build_signatures(self) -> List[FingerprintSignature]:
        """Build JavaScript framework signatures"""
        return [
            # React
            FingerprintSignature(
                name="React",
                category="library",
                scripts=[
                    re.compile(r"react", re.I),
                    re.compile(r"react-dom", re.I),
                    re.compile(r"createElement", re.I),
                ],
                body_patterns=[
                    re.compile(r"data-reactroot", re.I),
                    re.compile(r"data-reactid", re.I),
                    re.compile(r"__REACT_DEVTOOLS_GLOBAL_HOOK__", re.I),
                ],
                confidence_base=0.85,
            ),

            # Next.js
            FingerprintSignature(
                name="Next.js",
                category="framework",
                scripts=[
                    re.compile(r"_next/static/", re.I),
                    re.compile(r"__NEXT_DATA__", re.I),
                    re.compile(r"next/router", re.I),
                    re.compile(r"next/link", re.I),
                ],
                body_patterns=[
                    re.compile(r'id="__next"', re.I),
                    re.compile(r"__NEXT_DATA__", re.I),
                ],
                meta_tags={"next-head-count": re.compile(r".+")},
                confidence_base=0.9,
            ),

            # Vue.js
            FingerprintSignature(
                name="Vue.js",
                category="library",
                scripts=[
                    re.compile(r"vue\.runtime", re.I),
                    re.compile(r"vue\.global", re.I),
                    re.compile(r"createApp", re.I),
                    re.compile(r"Vue\.createApp", re.I),
                ],
                body_patterns=[
                    re.compile(r"data-v-", re.I),
                    re.compile(r"v-cloak", re.I),
                    re.compile(r"v-app", re.I),
                    re.compile(r"__VUE__", re.I),
                ],
                confidence_base=0.85,
            ),

            # Nuxt.js
            FingerprintSignature(
                name="Nuxt.js",
                category="framework",
                scripts=[re.compile(r"_nuxt/", re.I)],
                body_patterns=[re.compile(r"data-n-head", re.I), re.compile(r"__NUXT__", re.I)],
                confidence_base=0.9,
            ),

            # Angular
            FingerprintSignature(
                name="Angular",
                category="framework",
                scripts=[
                    re.compile(r"angular", re.I),
                    re.compile(r"@angular", re.I),
                    re.compile(r"zone\.js", re.I),
                    re.compile(r"rxjs", re.I),
                ],
                body_patterns=[
                    re.compile(r"ng-app", re.I),
                    re.compile(r"ng-version", re.I),
                    re.compile(r"ng-", re.I),
                ],
                meta_tags={"ng-version": re.compile(r".+")},
                confidence_base=0.85,
            ),

            # Svelte
            FingerprintSignature(
                name="Svelte",
                category="framework",
                scripts=[re.compile(r"svelte", re.I)],
                body_patterns=[re.compile(r"svelte-", re.I), re.compile(r"__SVELTE__", re.I)],
                confidence_base=0.85,
            ),

            # jQuery
            FingerprintSignature(
                name="jQuery",
                category="library",
                scripts=[re.compile(r"jquery", re.I)],
                version_extractors=[re.compile(r"jquery[.-](\d+\.\d+\.\d+)")],
                confidence_base=0.9,
            ),

            # Bootstrap
            FingerprintSignature(
                name="Bootstrap",
                category="library",
                scripts=[re.compile(r"bootstrap", re.I)],
                body_patterns=[re.compile(r"bootstrap", re.I)],
                version_extractors=[re.compile(r"bootstrap[.-](\d+\.\d+\.\d+)")],
                confidence_base=0.8,
            ),

            # Tailwind CSS
            FingerprintSignature(
                name="Tailwind CSS",
                category="library",
                body_patterns=[re.compile(r"tailwind", re.I)],
                confidence_base=0.7,
            ),

            # Alpine.js
            FingerprintSignature(
                name="Alpine.js",
                category="library",
                scripts=[re.compile(r"alpine", re.I)],
                body_patterns=[re.compile(r"x-data", re.I), re.compile(r"x-show", re.I)],
                confidence_base=0.8,
            ),

            # htmx
            FingerprintSignature(
                name="htmx",
                category="library",
                scripts=[re.compile(r"htmx", re.I)],
                body_patterns=[re.compile(r"hx-", re.I)],
                confidence_base=0.8,
            ),

            # Stimulus
            FingerprintSignature(
                name="Stimulus",
                category="library",
                scripts=[re.compile(r"stimulus", re.I)],
                body_patterns=[re.compile(r"data-controller", re.I), re.compile(r"data-action", re.I)],
                confidence_base=0.8,
            ),

            # Livewire
            FingerprintSignature(
                name="Livewire",
                category="library",
                scripts=[re.compile(r"livewire", re.I)],
                body_patterns=[re.compile(r"wire:", re.I)],
                confidence_base=0.8,
            ),
        ]

    async def fingerprint(self, target, http_client) -> List:
        """Fingerprint JavaScript technologies"""
        results = []

        try:
            resp = await http_client.get_with_browser_headers(target.url)
            if resp.status != 200:
                return results

            # Parse HTML
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract scripts
            scripts = []
            for script in soup.find_all("script"):
                src = script.get("src", "")
                content = script.string or ""
                if src:
                    scripts.append(src)
                if content:
                    scripts.append(content[:10000])  # Limit size

            # Extract body text
            body_text = soup.get_text()

            # Extract meta tags
            meta_tags = {}
            for meta in soup.find_all("meta"):
                name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
                content = meta.get("content", "")
                if name:
                    meta_tags[name.lower()] = content

            # Check signatures
            for sig in self.signatures:
                confidence = 0.0
                matches = []

                # Check scripts
                for script in scripts:
                    for pattern in sig.scripts:
                        if pattern.search(script):
                            confidence += 0.3
                            matches.append(f"script:{pattern.pattern}")

                # Check body patterns
                for pattern in sig.body_patterns:
                    if pattern.search(body_text):
                        confidence += 0.4
                        matches.append(f"body:{pattern.pattern}")

                # Check meta tags
                for meta_name, meta_pattern in sig.meta_tags.items():
                    if meta_name in meta_tags:
                        if meta_pattern.search(meta_tags[meta_name]):
                            confidence += 0.3
                            matches.append(f"meta:{meta_name}")

                if confidence > 0:
                    from src.core.models import Technology, Fingerprint
                    tech = Technology(
                        name=sig.name,
                        category=sig.category,
                        confidence=min(confidence, 1.0),
                    )

                    fp = Fingerprint(
                        technology=tech,
                        matches=matches,
                        confidence=min(confidence, 1.0),
                        source="js",
                    )
                    results.append(fp)

        except Exception as e:
            self.logger.error(f"JS fingerprinting failed: {e}")

        return results
