"""
ZDay Scanner - Local Fingerprint Database
1000+ signatures for technologies
"""
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict

from ..fingerprinting.base import FingerprintSignature


@dataclass
class FingerprintDB:
    """Local fingerprint database"""

    signatures: List[FingerprintSignature] = field(default_factory=list)
    _by_category: Dict[str, List[FingerprintSignature]] = field(default_factory=dict)
    _by_name: Dict[str, FingerprintSignature] = field(default_factory=dict)

    def __post_init__(self):
        self._index()

    def _index(self):
        """Build indexes"""
        self._by_category.clear()
        self._by_name.clear()

        for sig in self.signatures:
            cat = sig.category.lower()
            if cat not in self._by_category:
                self._by_category[cat] = []
            self._by_category[cat].append(sig)

            key = sig.name.lower()
            if key not in self._by_name:
                self._by_name[key] = sig

    def add(self, signature: FingerprintSignature):
        """Add a signature"""
        self.signatures.append(signature)
        self._index()

    def get_by_category(self, category: str) -> List[FingerprintSignature]:
        """Get signatures by category"""
        return self._by_category.get(category.lower(), [])

    def get_by_name(self, name: str) -> Optional[FingerprintSignature]:
        """Get signature by name"""
        return self._by_name.get(name.lower())

    def get_all(self) -> List[FingerprintSignature]:
        """Get all signatures"""
        return self.signatures

    def save_json(self, path: str):
        """Save to JSON file"""
        data = []
        for sig in self.signatures:
            data.append({
                "name": sig.name,
                "version": sig.version,
                "category": sig.category,
                "confidence_base": sig.confidence_base,
                "cpe": sig.cpe,
                "headers": {k: v.pattern if hasattr(v, 'pattern') else v for k, v in sig.headers.items()},
                "cookies": {k: v.pattern if hasattr(v, 'pattern') else v for k, v in sig.cookies.items()},
                "meta_tags": {k: v.pattern if hasattr(v, 'pattern') else v for k, v in sig.meta_tags.items()},
                "scripts": [p.pattern if hasattr(p, 'pattern') else p for p in sig.scripts],
                "body_patterns": [p.pattern if hasattr(p, 'pattern') else p for p in sig.body_patterns],
                "url_patterns": [p.pattern if hasattr(p, 'pattern') else p for p in sig.url_patterns],
                "version_extractors": [p.pattern if hasattr(p, 'pattern') else p for p in sig.version_extractors],
            })

        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load_json(cls, path: str) -> "FingerprintDB":
        """Load from JSON file"""
        with open(path, 'r') as f:
            data = json.load(f)

        db = cls()
        for item in data:
            sig = FingerprintSignature(
                name=item["name"],
                version=item.get("version"),
                category=item.get("category", "unknown"),
                confidence_base=item.get("confidence_base", 0.7),
                cpe=item.get("cpe"),
            )

            # Compile patterns
            for k, v in item.get("headers", {}).items():
                sig.headers[k] = re.compile(v, re.IGNORECASE)
            for k, v in item.get("cookies", {}).items():
                sig.cookies[k] = re.compile(v, re.IGNORECASE)
            for k, v in item.get("meta_tags", {}).items():
                sig.meta_tags[k] = re.compile(v, re.IGNORECASE)
            for p in item.get("scripts", []):
                sig.scripts.append(re.compile(p, re.IGNORECASE))
            for p in item.get("body_patterns", []):
                sig.body_patterns.append(re.compile(p, re.IGNORECASE))
            for p in item.get("url_patterns", []):
                sig.url_patterns.append(re.compile(p, re.IGNORECASE))
            for p in item.get("version_extractors", []):
                sig.version_extractors.append(re.compile(p, re.IGNORECASE) if isinstance(p, str) else p)

            db.add(sig)

        return db

    def stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        cats = defaultdict(int)
        for sig in self.signatures:
            cats[sig.category] += 1

        return {
            "total_signatures": len(self.signatures),
            "by_category": dict(cats),
        }


def create_default_database() -> FingerprintDB:
    """Create a default fingerprint database with common signatures"""
    db = FingerprintDB()

    # Add a comprehensive set of signatures (abbreviated for space)
    # In production, this would load from a large JSON file

    signatures_data = [
        # Servers
        {"name": "Apache", "category": "server", "headers": {"Server": "Apache"}, "confidence_base": 0.9},
        {"name": "nginx", "category": "server", "headers": {"Server": "nginx"}, "confidence_base": 0.9},
        {"name": "Microsoft-IIS", "category": "server", "headers": {"Server": "Microsoft-IIS"}, "confidence_base": 0.9},
        {"name": "LiteSpeed", "category": "server", "headers": {"Server": "LiteSpeed"}, "confidence_base": 0.9},
        {"name": "Caddy", "category": "server", "headers": {"Server": "Caddy"}, "confidence_base": 0.9},
        {"name": "OpenResty", "category": "server", "headers": {"Server": "OpenResty"}, "confidence_base": 0.9},

        # Languages
        {"name": "PHP", "category": "language", "headers": {"X-Powered-By": "PHP"}, "cookies": {"PHPSESSID": ".*"}, "confidence_base": 0.8},
        {"name": "Python", "category": "language", "headers": {"Server": "Python"}, "confidence_base": 0.7},
        {"name": "Node.js", "category": "language", "headers": {"X-Powered-By": "Express"}, "confidence_base": 0.7},

        # Frameworks
        {"name": "Django", "category": "framework", "cookies": {"csrftoken": ".*", "sessionid": ".*"}, "meta_tags": {"csrf-token": ".*"}, "body_patterns": ["csrfmiddlewaretoken"], "confidence_base": 0.85},
        {"name": "Flask", "category": "framework", "headers": {"Server": "Werkzeug"}, "cookies": {"session": ".*"}, "confidence_base": 0.75},
        {"name": "Express", "category": "framework", "headers": {"X-Powered-By": "Express"}, "cookies": {"connect.sid": ".*"}, "confidence_base": 0.8},
        {"name": "Spring", "category": "framework", "headers": {"Server": "Spring"}, "cookies": {"JSESSIONID": ".*"}, "confidence_base": 0.85},
        {"name": "Laravel", "category": "framework", "cookies": {"laravel_session": ".*", "XSRF-TOKEN": ".*"}, "confidence_base": 0.85},
        {"name": "Ruby on Rails", "category": "framework", "headers": {"X-Powered-By": "Phusion Passenger"}, "cookies": {"_session_id": ".*"}, "confidence_base": 0.85},
        {"name": "ASP.NET Core", "category": "framework", "headers": {"Server": "Kestrel"}, "cookies": {".AspNetCore": ".*"}, "confidence_base": 0.85},
        {"name": "Next.js", "category": "framework", "scripts": ["_next/static/"], "body_patterns": ["__NEXT_DATA__", 'id="__next"'], "confidence_base": 0.9},
        {"name": "Nuxt.js", "category": "framework", "scripts": ["_nuxt/"], "body_patterns": ["__NUXT__"], "confidence_base": 0.9},

        # CMS
        {"name": "WordPress", "category": "cms", "meta_tags": {"generator": "WordPress"}, "body_patterns": ["wp-content", "wp-includes", "/wp-json/"], "scripts": ["wp-emoji-release.min.js"], "confidence_base": 0.95},
        {"name": "Drupal", "category": "cms", "meta_tags": {"generator": "Drupal"}, "headers": {"X-Generator": "Drupal", "X-Drupal-Cache": ".*"}, "cookies": {"SESS": ".*"}, "confidence_base": 0.95},
        {"name": "Joomla", "category": "cms", "meta_tags": {"generator": "Joomla"}, "body_patterns": ["joomla", "/media/jui/"], "confidence_base": 0.95},
        {"name": "Magento", "category": "cms", "cookies": {"frontend": ".*"}, "body_patterns": ["magento", "Mage.Cookies"], "confidence_base": 0.95},
        {"name": "Shopify", "category": "cms", "headers": {"Server": "Shopify"}, "cookies": {"cart_sig": ".*"}, "body_patterns": ["Shopify.theme", "cdn.shopify.com"], "confidence_base": 0.95},
        {"name": "Ghost", "category": "cms", "meta_tags": {"generator": "Ghost"}, "confidence_base": 0.9},

        # Cloud
        {"name": "Cloudflare", "category": "cloud", "headers": {"Server": "cloudflare", "CF-Ray": ".*"}, "confidence_base": 0.95},
        {"name": "AWS CloudFront", "category": "cloud", "headers": {"Server": "CloudFront", "Via": "CloudFront"}, "confidence_base": 0.9},
        {"name": "Google Cloud", "category": "cloud", "headers": {"Server": "Google Frontend"}, "confidence_base": 0.9},
        {"name": "Vercel", "category": "cloud", "headers": {"Server": "Vercel", "X-Vercel-Id": ".*"}, "confidence_base": 0.95},
        {"name": "Netlify", "category": "cloud", "headers": {"Server": "Netlify", "X-NF-Request-ID": ".*"}, "confidence_base": 0.95},
        {"name": "Heroku", "category": "cloud", "headers": {"Server": "Heroku", "Via": "Heroku"}, "confidence_base": 0.9},

        # WAF
        {"name": "Cloudflare WAF", "category": "waf", "headers": {"Server": "cloudflare", "CF-Ray": ".*"}, "cookies": {"__cf_bm": ".*", "cf_clearance": ".*"}, "confidence_base": 0.95},
        {"name": "AWS WAF", "category": "waf", "headers": {"X-Amzn-Waf": ".*"}, "confidence_base": 0.9},
        {"name": "Akamai", "category": "waf", "headers": {"Server": "Akamai", "X-Akamai": ".*"}, "cookies": {"ak_bmsc": ".*"}, "confidence_base": 0.9},
        {"name": "Imperva", "category": "waf", "headers": {"X-CDN": "Imperva", "X-Iinfo": ".*"}, "cookies": {"incap_ses": ".*"}, "confidence_base": 0.95},
        {"name": "F5 BIG-IP", "category": "waf", "headers": {"Server": "BIG-IP"}, "cookies": {"TS": ".*", "BIGipServer": ".*"}, "confidence_base": 0.9},
        {"name": "Sucuri", "category": "waf", "headers": {"Server": "Sucuri", "X-Sucuri-ID": ".*"}, "confidence_base": 0.95},
        {"name": "ModSecurity", "category": "waf", "headers": {"Server": "ModSecurity"}, "confidence_base": 0.8},

        # Libraries
        {"name": "React", "category": "library", "scripts": ["react", "ReactDOM"], "body_patterns": ["data-reactroot", "data-reactid"], "confidence_base": 0.85},
        {"name": "Vue.js", "category": "library", "scripts": ["vue"], "body_patterns": ["data-v-", "v-cloak", "v-app"], "confidence_base": 0.85},
        {"name": "Angular", "category": "library", "scripts": ["angular", "zone.js"], "body_patterns": ["ng-app", "ng-version"], "confidence_base": 0.85},
        {"name": "jQuery", "category": "library", "scripts": ["jquery"], "confidence_base": 0.9, "version_extractors": [r"jquery[.-](\d+\.\d+\.\d+)"]},
        {"name": "Bootstrap", "category": "library", "body_patterns": ["bootstrap"], "scripts": ["bootstrap"], "confidence_base": 0.8},
        {"name": "Tailwind CSS", "category": "library", "body_patterns": ["tailwind"], "confidence_base": 0.7},
    ]

    for item in signatures_data:
        sig = FingerprintSignature(
            name=item["name"],
            version=item.get("version"),
            category=item.get("category", "unknown"),
            confidence_base=item.get("confidence_base", 0.7),
            cpe=item.get("cpe"),
        )

        for k, v in item.get("headers", {}).items():
            sig.headers[k] = re.compile(v, re.IGNORECASE)
        for k, v in item.get("cookies", {}).items():
            sig.cookies[k] = re.compile(v, re.IGNORECASE)
        for k, v in item.get("meta_tags", {}).items():
            sig.meta_tags[k] = re.compile(v, re.IGNORECASE)
        for p in item.get("scripts", []):
            sig.scripts.append(re.compile(p, re.IGNORECASE))
        for p in item.get("body_patterns", []):
            sig.body_patterns.append(re.compile(p, re.IGNORECASE))
        for p in item.get("version_extractors", []):
            sig.version_extractors.append(re.compile(p, re.IGNORECASE) if isinstance(p, str) else p)

        db.add(sig)

    return db


# Global default database
DEFAULT_DB = create_default_database()
