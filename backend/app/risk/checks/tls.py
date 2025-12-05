import uuid, ssl, socket
from urllib.parse import urlparse
from datetime import datetime, timezone
from ..types import Finding

def check_tls(url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443

    if parsed.scheme != "https":
        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                title="HTTPS is not enabled",
                category="TLS",
                severity=9.0,
                confidence=0.95,
                description="HTTP traffic is not encrypted, which increases the risk of interception and tampering.",
                recommendation="Enable HTTPS and redirect all HTTP traffic to HTTPS.",
                evidence={"url": url},
            )
        )
        return findings

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                title="TLS handshake / certificate validation failed",
                category="TLS",
                severity=8.5,
                confidence=0.9,
                description="Unable to validate the TLS connection or certificate.",
                recommendation="Ensure a valid certificate chain is installed and TLS is configured correctly.",
                evidence={"error": str(e), "host": host, "port": port},
            )
        )
        return findings

    not_after = cert.get("notAfter")
    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 14:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    title="TLS certificate expires soon",
                    category="TLS",
                    severity=6.0 if days_left >= 0 else 8.5,
                    confidence=0.95,
                    description=f"The TLS certificate expires in {days_left} day(s).",
                    recommendation="Renew the certificate before it expires to avoid outages and trust errors.",
                    evidence={"notAfter": not_after, "days_left": days_left},
                )
            )

    return findings
