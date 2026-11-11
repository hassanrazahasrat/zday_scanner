"""
ZDay Scanner - Framework Fingerprinter
25+ frameworks (Django, Laravel, Express, Next.js, Spring, Rails, etc.)
"""
import re
from typing import List

from src.fingerprinting.base import FingerprinterBase, FingerprintSignature


class FrameworkFingerprinter(FingerprinterBase):
    """Fingerprints web frameworks"""

    name = "framework_fingerprinter"

    def __init__(self, config):
        super().__init__(config)
        self.signatures = self._build_signatures()

    def _build_signatures(self) -> List[FingerprintSignature]:
        """Build framework signatures"""
        return [
            # Django
            FingerprintSignature(
                name="Django",
                category="framework",
                cookies={"csrftoken": re.compile(r".+"), "sessionid": re.compile(r".+")},
                headers={"X-Frame-Options": re.compile(r"DENY", re.I)},
                meta_tags={"csrf-token": re.compile(r".+")},
                body_patterns=[re.compile(r"csrfmiddlewaretoken", re.I), re.compile(r"django", re.I)],
                scripts=[re.compile(r"django\.js", re.I)],
                confidence_base=0.85,
            ),

            # Laravel
            FingerprintSignature(
                name="Laravel",
                category="framework",
                cookies={"laravel_session": re.compile(r".+"), "XSRF-TOKEN": re.compile(r".+")},
                headers={"X-Powered-By": re.compile(r"Laravel", re.I)},
                body_patterns=[
                    re.compile(r"laravel", re.I),
                    re.compile(r"_token", re.I),
                    re.compile(r"Laravel\\", re.I),
                ],
                confidence_base=0.85,
            ),

            # Express.js
            FingerprintSignature(
                name="Express",
                category="framework",
                headers={"X-Powered-By": re.compile(r"Express", re.I)},
                cookies={"connect.sid": re.compile(r".+")},
                body_patterns=[re.compile(r"express", re.I)],
                confidence_base=0.8,
            ),

            # Next.js
            FingerprintSignature(
                name="Next.js",
                category="framework",
                scripts=[re.compile(r"_next/static/", re.I), re.compile(r"__NEXT_DATA__", re.I)],
                body_patterns=[re.compile(r'id="__next"', re.I), re.compile(r"__NEXT_DATA__", re.I)],
                meta_tags={"next-head-count": re.compile(r".+")},
                confidence_base=0.9,
            ),

            # Spring / Spring Boot
            FingerprintSignature(
                name="Spring",
                category="framework",
                headers={"Server": re.compile(r"Spring", re.I), "X-Application-Context": re.compile(r".+")},
                cookies={"JSESSIONID": re.compile(r".+")},
                body_patterns=[re.compile(r"spring", re.I), re.compile(r"_csrf", re.I), re.compile(r"Spring Boot", re.I)],
                confidence_base=0.85,
            ),

            # Ruby on Rails
            FingerprintSignature(
                name="Ruby on Rails",
                category="framework",
                headers={"X-Powered-By": re.compile(r"Phusion Passenger", re.I), "X-Runtime": re.compile(r".+")},
                cookies={"_session_id": re.compile(r".+"), "_rails_session": re.compile(r".+")},
                body_patterns=[re.compile(r"authenticity_token", re.I), re.compile(r"rails", re.I), re.compile(r"csrf-param", re.I)],
                confidence_base=0.85,
            ),

            # Flask
            FingerprintSignature(
                name="Flask",
                category="framework",
                headers={"Server": re.compile(r"Werkzeug", re.I)},
                cookies={"session": re.compile(r".+")},
                body_patterns=[re.compile(r"flask", re.I)],
                confidence_base=0.75,
            ),

            # FastAPI
            FingerprintSignature(
                name="FastAPI",
                category="framework",
                headers={"Server": re.compile(r"uvicorn", re.I)},
                body_patterns=[re.compile(r"fastapi", re.I), re.compile(r"openapi.json", re.I)],
                confidence_base=0.8,
            ),

            # NestJS
            FingerprintSignature(
                name="NestJS",
                category="framework",
                body_patterns=[re.compile(r"nestjs", re.I), re.compile(r"@nestjs", re.I)],
                scripts=[re.compile(r"nestjs", re.I)],
                confidence_base=0.8,
            ),

            # Koa
            FingerprintSignature(
                name="Koa",
                category="framework",
                headers={"X-Powered-By": re.compile(r"Koa", re.I)},
                body_patterns=[re.compile(r"koa", re.I)],
                confidence_base=0.75,
            ),

            # AdonisJS
            FingerprintSignature(
                name="AdonisJS",
                category="framework",
                cookies={"adonis-session": re.compile(r".+")},
                body_patterns=[re.compile(r"adonis", re.I)],
                confidence_base=0.8,
            ),

            # CakePHP
            FingerprintSignature(
                name="CakePHP",
                category="framework",
                cookies={"CAKEPHP": re.compile(r".+")},
                body_patterns=[re.compile(r"cakephp", re.I), re.compile(r"Cake\\", re.I)],
                confidence_base=0.85,
            ),

            # Symfony
            FingerprintSignature(
                name="Symfony",
                category="framework",
                cookies={"PHPSESSID": re.compile(r".+")},
                headers={"X-Debug-Token": re.compile(r".+")},
                body_patterns=[re.compile(r"symfony", re.I), re.compile(r"_token", re.I)],
                confidence_base=0.85,
            ),

            # CodeIgniter
            FingerprintSignature(
                name="CodeIgniter",
                category="framework",
                cookies={"ci_session": re.compile(r".+")},
                body_patterns=[re.compile(r"codeigniter", re.I)],
                confidence_base=0.8,
            ),

            # Yii
            FingerprintSignature(
                name="Yii",
                category="framework",
                cookies={"PHPSESSID": re.compile(r".+")},
                body_patterns=[re.compile(r"yii", re.I), re.compile(r"Yii::", re.I)],
                confidence_base=0.8,
            ),

            # Play Framework
            FingerprintSignature(
                name="Play Framework",
                category="framework",
                cookies={"PLAY_SESSION": re.compile(r".+")},
                headers={"X-Powered-By": re.compile(r"Play", re.I)},
                body_patterns=[re.compile(r"playframework", re.I)],
                confidence_base=0.85,
            ),

            # Grails
            FingerprintSignature(
                name="Grails",
                category="framework",
                headers={"X-Grails-Version": re.compile(r".+")},
                body_patterns=[re.compile(r"grails", re.I)],
                confidence_base=0.85,
            ),

            # Phoenix
            FingerprintSignature(
                name="Phoenix",
                category="framework",
                headers={"Server": re.compile(r"Cowboy", re.I)},
                body_patterns=[re.compile(r"phoenix", re.I), re.compile(r"plug", re.I)],
                confidence_base=0.8,
            ),

            # Gin
            FingerprintSignature(
                name="Gin",
                category="framework",
                headers={"Server": re.compile(r"Gin", re.I)},
                body_patterns=[re.compile(r"gin-gonic", re.I)],
                confidence_base=0.8,
            ),

            # Echo
            FingerprintSignature(
                name="Echo",
                category="framework",
                headers={"Server": re.compile(r"Echo", re.I)},
                body_patterns=[re.compile(r"labstack/echo", re.I)],
                confidence_base=0.8,
            ),

            # Revel
            FingerprintSignature(
                name="Revel",
                category="framework",
                headers={"X-Powered-By": re.compile(r"Revel", re.I)},
                body_patterns=[re.compile(r"revel", re.I)],
                confidence_base=0.8,
            ),

            # Beego
            FingerprintSignature(
                name="Beego",
                category="framework",
                headers={"X-Powered-By": re.compile(r"Beego", re.I)},
                body_patterns=[re.compile(r"beego", re.I)],
                confidence_base=0.8,
            ),

            # ASP.NET Core
            FingerprintSignature(
                name="ASP.NET Core",
                category="framework",
                headers={"Server": re.compile(r"Kestrel", re.I)},
                cookies={".AspNetCore": re.compile(r".+")},
                body_patterns=[re.compile(r"asp.net", re.I), re.compile(r"__RequestVerificationToken", re.I)],
                confidence_base=0.85,
            ),

            # Nancy
            FingerprintSignature(
                name="Nancy",
                category="framework",
                headers={"X-Powered-By": re.compile(r"Nancy", re.I)},
                body_patterns=[re.compile(r"nancyfx", re.I)],
                confidence_base=0.8,
            ),
        ]

    async def fingerprint(self, target, http_client) -> List:
        """Fingerprint frameworks"""
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
                    scripts.append(content[:10000])

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

                # Check headers
                for header_name, header_pattern in sig.headers.items():
                    header_val = resp.headers.get(header_name, "")
                    if header_pattern.search(header_val):
                        confidence += 0.4
                        matches.append(f"header:{header_name}")

                # Check cookies
                for cookie_name, cookie_pattern in sig.cookies.items():
                    cookie_val = resp.cookies.get(cookie_name, "")
                    if cookie_pattern.search(cookie_val):
                        confidence += 0.3
                        matches.append(f"cookie:{cookie_name}")

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
                        source="framework",
                    )
                    results.append(fp)

        except Exception as e:
            self.logger.error(f"Framework fingerprinting failed: {e}")

        return results
