"""
ZDay Scanner - Injection Detector
SQLi, XSS, Command Injection, NoSQLi, SSTI, LDAP, XPath
"""
import asyncio
import random
import string
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode

from .detection_engine import BaseDetector, DetectionContext, DetectionPhase
from src.core.models import Vulnerability, VulnerabilityType, Severity
from src.utils.http_client import HTTPResponse


class InjectionDetector(BaseDetector):
    """Comprehensive injection vulnerability detector"""

    def __init__(self, config):
        super().__init__(config)
        self.vuln_types = [
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.XSS,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.NOSQL_INJECTION,
            VulnerabilityType.SSTI,
            VulnerabilityType.LDAP_INJECTION,
            VulnerabilityType.XPATH_INJECTION,
        ]
        self.phase = DetectionPhase.ACTIVE

        # Payloads for different injection types
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            '" OR "1"="1',
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND 1=CONVERT(int,(SELECT @@version))--",
        ]

        self.nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$where": "sleep(5000)"}',
            '{"$regex": ".*"}',
        ]

        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>",
            '\"><script>alert(\'XSS\')</script>',
        ]

        self.cmd_payloads = [
            "; sleep 5",
            "| sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "&& sleep 5",
            "; ping -c 5 127.0.0.1",
        ]

        self.ssti_payloads = [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{self}}",
        ]

        self.ldap_payloads = [
            "*)(&",
            "*)(|(userPassword=*))",
            "admin)(&",
        ]

        self.xpath_payloads = [
            "' or '1'='1",
            "'] | //user/*[contains(.,'admin')] | ['",
        ]

    async def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Run all injection tests"""
        vulns = []

        # Get forms and inputs to test
        forms = await self._discover_forms(context)

        # Test each form/input
        for form in forms:
            # SQL Injection
            sql_vulns = await self._test_sql_injection(context, form)
            vulns.extend(sql_vulns)

            # NoSQL Injection
            nosql_vulns = await self._test_nosql_injection(context, form)
            vulns.extend(nosql_vulns)

            # XSS
            xss_vulns = await self._test_xss(context, form)
            vulns.extend(xss_vulns)

            # Command Injection
            cmd_vulns = await self._test_command_injection(context, form)
            vulns.extend(cmd_vulns)

            # SSTI
            ssti_vulns = await self._test_ssti(context, form)
            vulns.extend(ssti_vulns)

            # LDAP Injection
            ldap_vulns = await self._test_ldap_injection(context, form)
            vulns.extend(ldap_vulns)

            # XPath Injection
            xpath_vulns = await self._test_xpath_injection(context, form)
            vulns.extend(xpath_vulns)

        return vulns

    async def _discover_forms(self, context: DetectionContext) -> List[Dict[str, Any]]:
        """Discover forms and input points"""
        forms = []

        try:
            resp = await context.http_client.get_with_browser_headers(context.target.url)
            if resp.status == 200 and "text/html" in resp.headers.get("Content-Type", ""):
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")

                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()
                    action_url = action if action.startswith("http") else f"{context.target.url.rstrip('/')}/{action.lstrip('/')}"

                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            inputs.append({
                                "name": name,
                                "type": inp.get("type", "text"),
                                "value": inp.get("value", ""),
                            })

                    if inputs:
                        forms.append({
                            "url": action_url,
                            "method": method,
                            "inputs": inputs,
                        })
        except Exception:
            pass

        # Also test URL parameters
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(context.target.url)
        if parsed.query:
            params = parse_qs(parsed.query)
            forms.append({
                "url": context.target.url,
                "method": "GET",
                "inputs": [{"name": k, "type": "query", "value": v[0] if v else ""} for k, v in params.items()],
            })

        return forms

    async def _test_injection(self, context: DetectionContext, form: Dict, payloads: List[str], 
                              vuln_type: VulnerabilityType, check_func, 
                              severity: Severity = Severity.HIGH) -> List[Vulnerability]:
        """Generic injection test"""
        vulns = []

        for payload in payloads:
            for input_field in form["inputs"]:
                if input_field["type"] in ["submit", "button", "hidden", "image"]:
                    continue

                # Prepare test data
                test_data = {}
                for inp in form["inputs"]:
                    if inp["name"] == input_field["name"]:
                        test_data[inp["name"]] = payload
                    else:
                        test_data[inp["name"]] = inp["value"]

                try:
                    if form["method"] == "POST":
                        resp = await context.http_client.post(form["url"], data=test_data)
                    else:
                        resp = await context.http_client.get(form["url"], params=test_data)

                    if check_func(resp, payload):
                        vuln = self._create_vuln(
                            type=vuln_type,
                            severity=severity,
                            title=f"{vuln_type.value.replace('_', ' ').title()} in {input_field['name']}",
                            description=f"Potential {vuln_type.value} vulnerability detected in parameter '{input_field['name']}'",
                            location=form["url"],
                            parameter=input_field["name"],
                            payload=payload,
                            evidence=f"Response status: {resp.status}, length: {len(resp.content)}",
                            remediation=self._get_remediation(vuln_type),
                            cwe=self._get_cwe(vuln_type),
                            confidence=0.7,
                        )
                        vulns.append(vuln)
                        break  # Found vuln in this input, move to next

                except Exception:
                    continue

        return vulns

    def _get_remediation(self, vuln_type: VulnerabilityType) -> str:
        remediations = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries/prepared statements. Implement input validation and WAF.",
            VulnerabilityType.NOSQL_INJECTION: "Validate and sanitize input. Use query builders. Disable JavaScript execution in queries.",
            VulnerabilityType.XSS: "Implement CSP. Encode output. Validate input. Use HttpOnly cookies.",
            VulnerabilityType.COMMAND_INJECTION: "Avoid shell commands. Use built-in libraries. Validate/sanitize input. Use allowlists.",
            VulnerabilityType.SSTI: "Avoid user input in templates. Use sandboxed template engines. Implement CSP.",
            VulnerabilityType.LDAP_INJECTION: "Escape LDAP special characters. Use parameterized LDAP queries.",
            VulnerabilityType.XPATH_INJECTION: "Use parameterized XPath queries. Validate input.",
        }
        return remediations.get(vuln_type, "Implement proper input validation and output encoding.")

    def _get_cwe(self, vuln_type: VulnerabilityType) -> str:
        cwes = {
            VulnerabilityType.SQL_INJECTION: "CWE-89",
            VulnerabilityType.NOSQL_INJECTION: "CWE-943",
            VulnerabilityType.XSS: "CWE-79",
            VulnerabilityType.COMMAND_INJECTION: "CWE-78",
            VulnerabilityType.SSTI: "CWE-1336",
            VulnerabilityType.LDAP_INJECTION: "CWE-90",
            VulnerabilityType.XPATH_INJECTION: "CWE-643",
        }
        return cwes.get(vuln_type, "CWE-20")

    # Specific check functions
    def _check_sql_error(self, resp: HTTPResponse, payload: str) -> bool:
        """Check for SQL error messages"""
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.*SQL.*Server",
            r"OLE DB.*SQL Server",
            r"SQLServer JDBC Driver",
            r"Warning.*oci_.*",
            r"Oracle error",
            r"ORA-\d{5}",
            r"Microsoft.*ODBC.*SQL Server",
            r"Syntax error.*in query expression",
            r"Unclosed quotation mark",
        ]

        text = resp.text.lower()
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _check_blind_sql(self, resp: HTTPResponse, payload: str) -> bool:
        """Check for time-based blind SQLi (simplified)"""
        # In production, compare response times with baseline
        return resp.duration > 5.0

    def _check_nosql(self, resp: HTTPResponse, payload: str) -> bool:
        """Check for NoSQL injection"""
        # Look for error messages or unusual responses
        error_patterns = [
            r"MongoError",
            r"SyntaxError.*\$",
            r"BSON",
            r"Invalid query",
        ]
        text = resp.text
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _check_xss(self, resp: HTTPResponse, payload: str) -> bool:
        """Check for reflected XSS"""
        # Check if payload appears unescaped in response
        if payload in resp.text:
            # Check if it's in a script context or executable context
            # Simplified check
            return True
        return False

    def _check_command(self, resp: HTTPResponse, payload: str) -> bool:
        """Check for command injection"""
        # Time-based detection
        if resp.duration > 5.0:
            return True
        # Output-based detection
        patterns = [
            r"root:.*:0:0:",
            r"uid=\d+.*gid=\d+",
            r"Windows IP Configuration",
            r"PING.*127\.0\.0\.1",
        ]
        text = resp.text
        for pattern in patterns:
            if re.search(pattern, text):
                return True
        return False

    def _check_ssti(self, resp: HTTPResponse, payload: str) -> bool:
        """Check for SSTI"""
        # Check for evaluated expressions
        if "49" in resp.text and "{{7*7}}" in payload:
            return True
        if "49" in resp.text and "${7*7}" in payload:
            return True
        # Check for template engine objects
        patterns = [
            r"config.*object",
            r"self.*object",
            r"__class__",
            r"__mro__",
            r"subprocess",
        ]
        text = resp.text
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _check_ldap(self, resp: HTTPResponse, payload: str) -> bool:
        """Check for LDAP injection"""
        patterns = [
            r"LDAP.*error",
            r"javax\.naming",
            r"Invalid DN syntax",
            r"Bad search filter",
        ]
        text = resp.text
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _check_xpath(self, resp: HTTPResponse, payload: str) -> bool:
        """Check for XPath injection"""
        patterns = [
            r"XPath.*error",
            r"Invalid XPath",
            r"xmlXPathEval",
        ]
        text = resp.text
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    # Test methods
    async def _test_sql_injection(self, context: DetectionContext, form: Dict) -> List[Vulnerability]:
        return await self._test_injection(
            context, form, self.sql_payloads,
            VulnerabilityType.SQL_INJECTION,
            lambda r, p: self._check_sql_error(r, p) or self._check_blind_sql(r, p),
            Severity.HIGH
        )

    async def _test_nosql_injection(self, context: DetectionContext, form: Dict) -> List[Vulnerability]:
        return await self._test_injection(
            context, form, self.nosql_payloads,
            VulnerabilityType.NOSQL_INJECTION,
            self._check_nosql,
            Severity.HIGH
        )

    async def _test_xss(self, context: DetectionContext, form: Dict) -> List[Vulnerability]:
        return await self._test_injection(
            context, form, self.xss_payloads,
            VulnerabilityType.XSS,
            self._check_xss,
            Severity.MEDIUM
        )

    async def _test_command_injection(self, context: DetectionContext, form: Dict) -> List[Vulnerability]:
        return await self._test_injection(
            context, form, self.cmd_payloads,
            VulnerabilityType.COMMAND_INJECTION,
            self._check_command,
            Severity.CRITICAL
        )

    async def _test_ssti(self, context: DetectionContext, form: Dict) -> List[Vulnerability]:
        return await self._test_injection(
            context, form, self.ssti_payloads,
            VulnerabilityType.SSTI,
            self._check_ssti,
            Severity.CRITICAL
        )

    async def _test_ldap_injection(self, context: DetectionContext, form: Dict) -> List[Vulnerability]:
        return await self._test_injection(
            context, form, self.ldap_payloads,
            VulnerabilityType.LDAP_INJECTION,
            self._check_ldap,
            Severity.HIGH
        )

    async def _test_xpath_injection(self, context: DetectionContext, form: Dict) -> List[Vulnerability]:
        return await self._test_injection(
            context, form, self.xpath_payloads,
            VulnerabilityType.XPATH_INJECTION,
            self._check_xpath,
            Severity.HIGH
        )
