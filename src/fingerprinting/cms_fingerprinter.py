"""
ZDay Scanner - CMS Fingerprinter
Detects: 10+ CMSs (WordPress, Drupal, Joomla, Magento, Shopify, Ghost, etc.)
"""
import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup

from src.fingerprinting.base import FingerprinterBase, FingerprintSignature, register_fingerprinter
from src.core.config import ScannerConfig


@register_fingerprinter("cms")
class CMSFingerprinter(FingerprinterBase):
    """CMS fingerprinting"""

    def _load_signatures(self):
        self.signatures = [
            # WordPress
            FingerprintSignature(
                name="WordPress",
                category="cms",
                meta_tags={"generator": re.compile(r"WordPress", re.I)},
                headers={"X-Powered-By": re.compile(r"WordPress", re.I)},
                body_patterns=[
                    re.compile(r"wp-content", re.I),
                    re.compile(r"wp-includes", re.I),
                    re.compile(r"/wp-json/", re.I),
                    re.compile(r"wordpress", re.I),
                ],
                scripts=[re.compile(r"wp-emoji-release\.min\.js", re.I), re.compile(r"wp-embed\.min\.js", re.I)],
                url_patterns=[re.compile(r"/wp-admin/", re.I), re.compile(r"/wp-login\.php", re.I)],
                confidence_base=0.95,
            ),

            # Drupal
            FingerprintSignature(
                name="Drupal",
                category="cms",
                meta_tags={"generator": re.compile(r"Drupal", re.I)},
                headers={"X-Generator": re.compile(r"Drupal", re.I), "X-Drupal-Cache": re.compile(r".+")},
                cookies={"SESS": re.compile(r".+"), "Drupal.tableDrag": re.compile(r".+")},
                body_patterns=[
                    re.compile(r"drupal", re.I),
                    re.compile(r"/sites/default/", re.I),
                    re.compile(r"drupal\.js", re.I),
                    re.compile(r"jQuery\.extend.*Drupal", re.I),
                ],
                scripts=[re.compile(r"drupal", re.I)],
                url_patterns=[re.compile(r"/user/login", re.I), re.compile(r"/admin/", re.I)],
                confidence_base=0.95,
            ),

            # Joomla
            FingerprintSignature(
                name="Joomla",
                category="cms",
                meta_tags={"generator": re.compile(r"Joomla", re.I)},
                headers={"X-Content-Encoded-By": re.compile(r"Joomla", re.I)},
                cookies={"joomla": re.compile(r".+")},
                body_patterns=[
                    re.compile(r"joomla", re.I),
                    re.compile(r"/media/jui/", re.I),
                    re.compile(r"option=com_", re.I),
                    re.compile(r"Joomla!", re.I),
                ],
                url_patterns=[re.compile(r"/administrator/", re.I)],
                confidence_base=0.95,
            ),

            # Magento
            FingerprintSignature(
                name="Magento",
                category="cms",
                cookies={"frontend": re.compile(r".+"), "adminhtml": re.compile(r".+")},
                headers={"X-Magento": re.compile(r".+")},
                body_patterns=[
                    re.compile(r"magento", re.I),
                    re.compile(r"Mage\.Cookies", re.I),
                    re.compile(r"Mage\.Registry", re.I),
                    re.compile(r"skin/frontend/", re.I),
                ],
                scripts=[re.compile(r"mage/", re.I), re.compile(r"require\.js.*magento", re.I)],
                url_patterns=[re.compile(r"/admin/", re.I)],
                confidence_base=0.95,
            ),

            # Shopify
            FingerprintSignature(
                name="Shopify",
                category="cms",
                headers={"Server": re.compile(r"Shopify", re.I), "X-Shopify-Stage": re.compile(r".+")},
                cookies={"cart_sig": re.compile(r".+"), "secure_customer_sig": re.compile(r".+"), "_shopify_y": re.compile(r".+")},
                body_patterns=[
                    re.compile(r"Shopify\.theme", re.I),
                    re.compile(r"cdn\.shopify\.com", re.I),
                    re.compile(r"shopify", re.I),
                    re.compile(r"Shopify\.Analytics", re.I),
                ],
                scripts=[re.compile(r"shopify", re.I)],
                confidence_base=0.95,
            ),

            # Ghost
            FingerprintSignature(
                name="Ghost",
                category="cms",
                meta_tags={"generator": re.compile(r"Ghost", re.I)},
                headers={"X-Powered-By": re.compile(r"Ghost", re.I)},
                body_patterns=[
                    re.compile(r"ghost", re.I),
                    re.compile(r"/ghost/", re.I),
                    re.compile(r"ghost\.org", re.I),
                ],
                confidence_base=0.9,
            ),

            # Wix
            FingerprintSignature(
                name="Wix",
                category="cms",
                headers={"Server": re.compile(r"Wix", re.I), "X-Wix-Request-Id": re.compile(r".+")},
                body_patterns=[re.compile(r"wix", re.I), re.compile(r"Wix\.com", re.I)],
                confidence_base=0.9,
            ),

            # Squarespace
            FingerprintSignature(
                name="Squarespace",
                category="cms",
                headers={"Server": re.compile(r"Squarespace", re.I)},
                cookies={"ss_cid": re.compile(r".+"), "ss_cvt": re.compile(r".+")},
                body_patterns=[re.compile(r"squarespace", re.I), re.compile(r"static\.squarespace\.com", re.I)],
                confidence_base=0.9,
            ),

            # Webflow
            FingerprintSignature(
                name="Webflow",
                category="cms",
                headers={"Server": re.compile(r"Webflow", re.I)},
                body_patterns=[re.compile(r"webflow", re.I), re.compile(r"webflow\.js", re.I)],
                confidence_base=0.9,
            ),

            # Typo3
            FingerprintSignature(
                name="TYPO3",
                category="cms",
                meta_tags={"generator": re.compile(r"TYPO3", re.I)},
                cookies={"fe_typo_user": re.compile(r".+")},
                body_patterns=[re.compile(r"typo3", re.I), re.compile(r"TYPO3", re.I)],
                url_patterns=[re.compile(r"/typo3/", re.I)],
                confidence_base=0.9,
            ),

            # PrestaShop
            FingerprintSignature(
                name="PrestaShop",
                category="cms",
                cookies={"PrestaShop": re.compile(r".+")},
                body_patterns=[re.compile(r"PrestaShop", re.I), re.compile(r"prestashop", re.I)],
                confidence_base=0.9,
            ),

            # OpenCart
            FingerprintSignature(
                name="OpenCart",
                category="cms",
                cookies={"OCSESSID": re.compile(r".+")},
                body_patterns=[re.compile(r"OpenCart", re.I), re.compile(r"opencart", re.I)],
                confidence_base=0.9,
            ),
        ]

    async def fingerprint(self, target, http_client) -> List:
        """Perform CMS fingerprinting"""
        from src.core.models import Fingerprint

        results = []

        try:
            resp = await http_client.get_with_browser_headers(target.url)
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

            for sig in self.signatures:
                fp = self._match_signature(sig, data)
                if fp:
                    results.append(fp)

        except Exception:
            pass

        return results
