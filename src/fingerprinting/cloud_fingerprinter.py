"""
ZDay Scanner - Cloud Provider Fingerprinter
Detects: AWS, GCP, Azure, Cloudflare, Vercel, Netlify, Heroku, DigitalOcean, etc.
"""
import re
from typing import List, Dict, Any

from src.fingerprinting.base import FingerprinterBase, FingerprintSignature, register_fingerprinter
from src.core.config import ScannerConfig


@register_fingerprinter("cloud")
class CloudFingerprinter(FingerprinterBase):
    """Cloud provider fingerprinting"""

    def _load_signatures(self):
        self.signatures = [
            # AWS
            FingerprintSignature(
                name="AWS CloudFront",
                category="cloud",
                headers={
                    "Server": re.compile(r"CloudFront", re.I),
                    "Via": re.compile(r"CloudFront", re.I),
                    "X-Amz-Cf-Id": re.compile(r".+"),
                    "X-Amz-Cf-Pop": re.compile(r".+"),
                },
                confidence_base=0.95,
            ),
            FingerprintSignature(
                name="AWS S3",
                category="cloud",
                headers={
                    "Server": re.compile(r"AmazonS3", re.I),
                    "X-Amz-Request-Id": re.compile(r".+"),
                    "X-Amz-Id-2": re.compile(r".+"),
                },
                body_patterns=[re.compile(r"s3\.amazonaws\.com", re.I)],
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="AWS ALB/ELB",
                category="cloud",
                headers={
                    "Server": re.compile(r"awselb", re.I),
                    "X-Amzn-Trace-Id": re.compile(r".+"),
                },
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="AWS API Gateway",
                category="cloud",
                headers={"X-Amzn-Requestid": re.compile(r".+"), "X-Amz-Apigw-Id": re.compile(r".+")},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="AWS Lambda@Edge",
                category="cloud",
                headers={"X-Amz-Cf-Id": re.compile(r".+")},
                body_patterns=[re.compile(r"lambda", re.I)],
                confidence_base=0.7,
            ),

            # Google Cloud
            FingerprintSignature(
                name="Google Cloud Load Balancer",
                category="cloud",
                headers={
                    "Server": re.compile(r"Google Frontend", re.I),
                    "Via": re.compile(r"Google Frontend", re.I),
                    "X-Cloud-Trace-Context": re.compile(r".+"),
                },
                confidence_base=0.95,
            ),
            FingerprintSignature(
                name="Google App Engine",
                category="cloud",
                headers={"Server": re.compile(r"Google Frontend", re.I), "X-Appengine": re.compile(r".+")},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="Google Cloud Run",
                category="cloud",
                headers={"Server": re.compile(r"Google Frontend", re.I), "X-Cloud-Run": re.compile(r".+")},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="Firebase Hosting",
                category="cloud",
                headers={"Server": re.compile(r"Firebase", re.I), "X-Firebase": re.compile(r".+")},
                confidence_base=0.9,
            ),

            # Azure
            FingerprintSignature(
                name="Azure Front Door",
                category="cloud",
                headers={"Server": re.compile(r"Azure", re.I), "X-Azure-Ref": re.compile(r".+")},
                confidence_base=0.9,
            ),
            FingerprintSignature(
                name="Azure App Service",
                category="cloud",
                headers={"Server": re.compile(r"Microsoft-IIS", re.I), "X-Powered-By": re.compile(r"ASP\.NET", re.I)},
                cookies={"ARRAffinity": re.compile(r".+")},
                confidence_base=0.85,
            ),
            FingerprintSignature(
                name="Azure CDN",
                category="cloud",
                headers={"Server": re.compile(r"Azure", re.I), "X-Cache": re.compile(r".+")},
                confidence_base=0.8,
            ),

            # Cloudflare
            FingerprintSignature(
                name="Cloudflare",
                category="cloud",
                headers={
                    "Server": re.compile(r"cloudflare", re.I),
                    "CF-Ray": re.compile(r".+"),
                    "CF-Cache-Status": re.compile(r".+"),
                    "CF-Request-ID": re.compile(r".+"),
                },
                confidence_base=0.95,
            ),

            # Vercel
            FingerprintSignature(
                name="Vercel",
                category="cloud",
                headers={
                    "Server": re.compile(r"Vercel", re.I),
                    "X-Vercel-Id": re.compile(r".+"),
                    "X-Vercel-Cache": re.compile(r".+"),
                },
                confidence_base=0.95,
            ),

            # Netlify
            FingerprintSignature(
                name="Netlify",
                category="cloud",
                headers={
                    "Server": re.compile(r"Netlify", re.I),
                    "X-NF-Request-ID": re.compile(r".+"),
                    "Age": re.compile(r".+"),
                },
                cookies={"nf_": re.compile(r".+")},
                confidence_base=0.95,
            ),

            # Heroku
            FingerprintSignature(
                name="Heroku",
                category="cloud",
                headers={
                    "Server": re.compile(r"Heroku", re.I),
                    "Via": re.compile(r"Heroku", re.I),
                    "X-Request-ID": re.compile(r".+"),
                },
                confidence_base=0.9,
            ),

            # DigitalOcean
            FingerprintSignature(
                name="DigitalOcean App Platform",
                category="cloud",
                headers={"Server": re.compile(r"DigitalOcean", re.I), "X-DO-App-Platform": re.compile(r".+")},
                confidence_base=0.9,
            ),

            # Render
            FingerprintSignature(
                name="Render",
                category="cloud",
                headers={"Server": re.compile(r"Render", re.I), "X-Render-Origin": re.compile(r".+")},
                confidence_base=0.9,
            ),

            # Fly.io
            FingerprintSignature(
                name="Fly.io",
                category="cloud",
                headers={"Server": re.compile(r"Fly", re.I), "Fly-Request-ID": re.compile(r".+")},
                confidence_base=0.9,
            ),

            # Railway
            FingerprintSignature(
                name="Railway",
                category="cloud",
                headers={"Server": re.compile(r"Railway", re.I), "X-Railway": re.compile(r".+")},
                confidence_base=0.9,
            ),

            # Fastly
            FingerprintSignature(
                name="Fastly",
                category="cloud",
                headers={"Server": re.compile(r"Fastly", re.I), "Fastly-Debug-Digest": re.compile(r".+")},
                confidence_base=0.9,
            ),

            # Akamai
            FingerprintSignature(
                name="Akamai",
                category="cloud",
                headers={"Server": re.compile(r"Akamai", re.I), "X-Akamai": re.compile(r".+")},
                confidence_base=0.9,
            ),
        ]

    async def fingerprint(self, target, http_client) -> List:
        """Perform cloud fingerprinting"""
        from src.core.models import Fingerprint

        results = []

        try:
            resp = await http_client.get_with_browser_headers(target.url)

            data = {
                "url": str(resp.url),
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "cookies": resp.cookies,
                "body": resp.text,
            }

            for sig in self.signatures:
                fp = self._match_signature(sig, data)
                if fp:
                    results.append(fp)

        except Exception:
            pass

        return results
