"""
ZDay Scanner - HTTP Fingerprinter
Detects technologies from HTTP headers, body, cookies, meta tags
"""
import re
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup

from src.fingerprinting.base import FingerprinterBase, FingerprintSignature, register_fingerprinter
from src.core.models import Technology
from src.core.config import ScannerConfig


@register_fingerprinter("http")
class HTTPFingerprinter(FingerprinterBase):
    """HTTP-based technology fingerprinting"""

    def _load_signatures(self):
        """Load HTTP fingerprint signatures"""
        self.signatures = [
            # Web Servers
            FingerprintSignature(
                name="Apache",
                category="server",
                headers={"Server": re.compile(r"Apache", re.I)},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="nginx",
                category="server",
                headers={"Server": re.compile(r"nginx", re.I)},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="Microsoft-IIS",
                category="server",
                headers={"Server": re.compile(r"Microsoft-IIS", re.I)},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="LiteSpeed",
                category="server",
                headers={"Server": re.compile(r"LiteSpeed", re.I)},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="Caddy",
                category="server",
                headers={"Server": re.compile(r"Caddy", re.I)},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="OpenResty",
                category="server",
                headers={"Server": re.compile(r"OpenResty", re.I)},
                confidence_base=0.9,
            ),

            # PHP
            FingerprintSignature(
                name="PHP",
                category="language",
                headers={"X-Powered-By": re.compile(r"PHP", re.I)},
                cookies={"PHPSESSID": re.compile(r".+")},
                body_patterns=[re.compile(r"\.php", re.I)],
                confidence_base=0.8,
            ),

            # ASP.NET
            FingerprintSignature(
                name="ASP.NET",
                category="framework",
                headers={
                    "X-Powered-By": re.compile(r"ASP\.NET", re.I),
                    "X-AspNet-Version": re.compile(r".+"),
                    "X-AspNetMvc-Version": re.compile(r".+"),
                },
                cookies={"ASP.NET_SessionId": re.compile(r".+")},
                body_patterns=[re.compile(r"__VIEWSTATE", re.I), re.compile(r"\.aspx", re.I)],
                confidence_base=0.9,
            ),

            # Express.js
            FingerprintSignature(
                name="Express",
                category="framework",
                headers={"X-Powered-By": re.compile(r"Express", re.I)},
                cookies={"connect.sid": re.compile(r".+")},
                confidence_base=0.8,
            ),

            # Django
            FingerprintSignature(
                name="Django",
                category="framework",
                headers={"Server": re.compile(r"Django", re.I)},
                cookies={"csrftoken": re.compile(r".+"), "sessionid": re.compile(r".+")},
                meta_tags={"csrf-token": re.compile(r".+")},
                body_patterns=[re.compile(r"csrfmiddlewaretoken", re.I)],
                confidence_base=0.85,
            ),

            # Ruby on Rails
            FingerprintSignature(
                name="Ruby on Rails",
                category="framework",
                headers={"X-Powered-By": re.compile(r"Phusion Passenger", re.I)},
                cookies={"_session_id": re.compile(r".+")},
                body_patterns=[re.compile(r"authenticity_token", re.I), re.compile(r"rails", re.I)],
                confidence_base=0.8,
            ),

            # Flask
            FingerprintSignature(
                name="Flask",
                category="framework",
                cookies={"session": re.compile(r".+")},
                body_patterns=[re.compile(r"flask", re.I)],
                confidence_base=0.7,
            ),

            # Spring
            FingerprintSignature(
                name="Spring",
                category="framework",
                headers={"Server": re.compile(r"Spring", re.I)},
                cookies={"JSESSIONID": re.compile(r".+")},
                body_patterns=[re.compile(r"spring", re.I), re.compile(r"_csrf", re.I)],
                confidence_base=0.8,
            ),

            # WordPress
            FingerprintSignature(
                name="WordPress",
                category="cms",
                meta_tags={"generator": re.compile(r"WordPress", re.I)},
                body_patterns=[
                    re.compile(r"wp-content", re.I),
                    re.compile(r"wp-includes", re.I),
                    re.compile(r"/wp-json/", re.I),
                ],
                scripts=[re.compile(r"wp-emoji-release\.min\.js", re.I)],
                confidence_base=0.9,
            ),

            # Drupal
            FingerprintSignature(
                name="Drupal",
                category="cms",
                meta_tags={"generator": re.compile(r"Drupal", re.I)},
                headers={"X-Generator": re.compile(r"Drupal", re.I)},
                cookies={"SESS": re.compile(r".+")},
                body_patterns=[re.compile(r"drupal", re.I), re.compile(r"/sites/default/", re.I)],
                confidence_base=0.9,
            ),

            # Joomla
            FingerprintSignature(
                name="Joomla",
                category="cms",
                meta_tags={"generator": re.compile(r"Joomla", re.I)},
                body_patterns=[re.compile(r"joomla", re.I), re.compile(r"/media/jui/", re.I)],
                confidence_base=0.9,
            ),

            # Magento
            FingerprintSignature(
                name="Magento",
                category="cms",
                cookies={"frontend": re.compile(r".+")},
                body_patterns=[re.compile(r"magento", re.I), re.compile(r"Mage\.Cookies", re.I)],
                confidence_base=0.9,
            ),

            # Shopify
            FingerprintSignature(
                name="Shopify",
                category="cms",
                headers={"Server": re.compile(r"Shopify", re.I)},
                cookies={"cart_sig": re.compile(r".+"), "secure_customer_sig": re.compile(r".+")},
                body_patterns=[re.compile(r"Shopify\.theme", re.I), re.compile(r"cdn\.shopify\.com", re.I)],
                confidence_base=0.95,
            ),

            # Ghost
            FingerprintSignature(
                name="Ghost",
                category="cms",
                meta_tags={"generator": re.compile(r"Ghost", re.I)},
                body_patterns=[re.compile(r"ghost", re.I), re.compile(r"/ghost/", re.I)],
                confidence_base=0.9,
            ),

            # React
            FingerprintSignature(
                name="React",
                category="library",
                scripts=[re.compile(r"react", re.I), re.compile(r"ReactDOM", re.I)],
                body_patterns=[re.compile(r"data-reactroot", re.I), re.compile(r"react-dom", re.I)],
                confidence_base=0.8,
            ),

            # Vue.js
            FingerprintSignature(
                name="Vue.js",
                category="library",
                scripts=[re.compile(r"vue", re.I), re.compile(r"Vue\.js", re.I)],
                body_patterns=[re.compile(r"v-app", re.I), re.compile(r"data-v-", re.I)],
                confidence_base=0.8,
            ),

            # Angular
            FingerprintSignature(
                name="Angular",
                category="framework",
                scripts=[re.compile(r"angular", re.I), re.compile(r"ng-version", re.I)],
                body_patterns=[re.compile(r"ng-app", re.I), re.compile(r"ng-version", re.I)],
                confidence_base=0.8,
            ),

            # jQuery
            FingerprintSignature(
                name="jQuery",
                category="library",
                scripts=[re.compile(r"jquery", re.I)],
                confidence_base=0.9,
                version_extractors=[re.compile(r"jquery[.-](\d+\.\d+\.\d+)", re.I)],
            ),

            # Bootstrap
            FingerprintSignature(
                name="Bootstrap",
                category="library",
                body_patterns=[re.compile(r"bootstrap", re.I)],
                scripts=[re.compile(r"bootstrap", re.I)],
                confidence_base=0.8,
            ),

            # Cloudflare
            FingerprintSignature(
                name="Cloudflare",
                category="waf",
                headers={
                    "Server": re.compile(r"cloudflare", re.I),
                    "CF-Ray": re.compile(r".+"),
                },
                confidence_base=0.95,
            ),

            # AWS
            FingerprintSignature(
                name="AWS CloudFront",
                category="cloud",
                headers={"Server": re.compile(r"CloudFront", re.I), "Via": re.compile(r"CloudFront", re.I)},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="AWS ELB",
                category="cloud",
                headers={"Server": re.compile(r"awselb", re.I)},
                confidence_base=0.8,
            ),

            # Google Cloud
            FingerprintSignature(
                name="Google Cloud",
                category="cloud",
                headers={"Server": re.compile(r"Google Frontend", re.I), "Via": re.compile(r"Google Frontend", re.I)},
                confidence_base=0.9,
            ),

            # Vercel
            FingerprintSignature(
                name="Vercel",
                category="cloud",
                headers={"Server": re.compile(r"Vercel", re.I), "X-Vercel-Id": re.compile(r".+")},
                confidence_base=0.95,
            ),

            # Netlify
            FingerprintSignature(
                name="Netlify",
                category="cloud",
                headers={"Server": re.compile(r"Netlify", re.I), "X-NF-Request-ID": re.compile(r".+")},
                confidence_base=0.95,
            ),

            # Heroku
            FingerprintSignature(
                name="Heroku",
                category="cloud",
                headers={"Server": re.compile(r"Heroku", re.I), "Via": re.compile(r"Heroku", re.I)},
                confidence_base=0.9,
            ),

            # WAF Signatures
            FingerprintSignature(
                name="AWS WAF",
                category="waf",
                headers={"X-Amzn-Waf": re.compile(r".+")},
                body_patterns=[re.compile(r"aws.*waf", re.I)],
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="Akamai",
                category="waf",
                headers={"Server": re.compile(r"Akamai", re.I), "X-Akamai": re.compile(r".+")},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="Imperva",
                category="waf",
                headers={"X-CDN": re.compile(r"Imperva", re.I), "X-Iinfo": re.compile(r".+")},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="F5 BIG-IP",
                category="waf",
                headers={"Server": re.compile(r"BIG-IP", re.I)},
                cookies={"TS": re.compile(r".+")},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="Sucuri",
                category="waf",
                headers={"Server": re.compile(r"Sucuri", re.I), "X-Sucuri-ID": re.compile(r".+")},
                confidence_base=0.95,
            ),
            FingerprintSignature(
                name="ModSecurity",
                category="waf",
                headers={"Server": re.compile(r"ModSecurity", re.I)},
                body_patterns=[re.compile(r"ModSecurity", re.I)],
                confidence_base=0.8,
            ),
        ]

    async def fingerprint(self, target, http_client) -> List:
        """Perform HTTP fingerprinting"""
        from src.core.models import Fingerprint

        results = []

        try:
            # Get main page
            resp = await http_client.get_with_browser_headers(target.url)

            # Prepare data for matching
            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract meta tags
            meta_tags = {}
            for meta in soup.find_all("meta"):
                name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
                content = meta.get("content", "")
                if name:
                    meta_tags[name.lower()] = content

            # Extract scripts
            scripts = []
            for script in soup.find_all("script"):
                src = script.get("src", "")
                content = script.string or ""
                if src:
                    scripts.append(src)
                if content:
                    scripts.append(content[:5000])

            data = {
                "url": str(resp.url),
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "cookies": resp.cookies,
                "meta_tags": meta_tags,
                "scripts": scripts,
                "body": resp.text,
            }

            # Match signatures
            for sig in self.signatures:
                fp = self._match_signature(sig, data)
                if fp:
                    results.append(fp)

        except Exception as e:
            pass

        return results
