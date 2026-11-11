"""
ZDay Scanner - TLS Fingerprinter
JA3/SSL certificate analysis
"""
import ssl
import socket
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.fingerprinting.base import FingerprinterBase, FingerprintSignature, register_fingerprinter
from src.core.config import ScannerConfig


@register_fingerprinter("tls")
class TLSFingerprinter(FingerprinterBase):
    """TLS/SSL fingerprinting"""

    def _load_signatures(self):
        # TLS fingerprinting doesn't use traditional signatures
        # Instead it analyzes certificate and JA3
        self.signatures = []

    async def fingerprint(self, target, http_client) -> List:
        """Perform TLS fingerprinting"""
        from src.core.models import Fingerprint, Technology

        results = []

        try:
            from urllib.parse import urlparse
            parsed = urlparse(target.url)
            hostname = parsed.hostname
            port = parsed.port or 443

            if parsed.scheme != "https":
                return results

            # Get certificate info
            cert_info = await self._get_certificate_info(hostname, port)
            if cert_info:
                tech = Technology(
                    name="TLS Certificate",
                    category="crypto",
                    version=cert_info.get("version"),
                    confidence=0.9,
                    evidence=[f"Issuer: {cert_info.get('issuer')}", f"Valid until: {cert_info.get('not_after')}"],
                    cpe=None,
                )
                fp = Fingerprint(
                    technology=tech,
                    matches=["tls_certificate"],
                    confidence=0.9,
                    source="tls",
                    metadata=cert_info,
                )
                results.append(fp)

            # JA3 fingerprint
            ja3 = await self._get_ja3_fingerprint(hostname, port)
            if ja3:
                tech = Technology(
                    name="JA3 Fingerprint",
                    category="crypto",
                    version=ja3,
                    confidence=0.7,
                    evidence=[f"JA3: {ja3}"],
                )
                fp = Fingerprint(
                    technology=tech,
                    matches=["ja3"],
                    confidence=0.7,
                    source="tls",
                    metadata={"ja3": ja3},
                )
                results.append(fp)

        except Exception:
            pass

        return results

    async def _get_certificate_info(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    return {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": version,
                        "cipher": cipher[0] if cipher else None,
                        "cipher_bits": cipher[2] if cipher else None,
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": [x[1] for x in cert.get("subjectAltName", [])],
                        "serial_number": cert.get("serialNumber"),
                    }
        except Exception:
            return None

    async def _get_ja3_fingerprint(self, hostname: str, port: int) -> Optional[str]:
        """Calculate JA3 fingerprint (simplified)"""
        # Full JA3 requires parsing ClientHello - this is a placeholder
        # In production, use a library like ja3 or implement TLS ClientHello parsing
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get cipher suite
                    cipher = ssock.cipher()
                    if cipher:
                        return f"JA3:{cipher[0]}:{ssock.version()}"
        except Exception:
            pass
        return None
