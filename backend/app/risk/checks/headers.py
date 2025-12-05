import uuid
from ..types import Finding

RECOMMENDED = {
    "strict-transport-security": (
        "Missing HSTS (Strict-Transport-Security)",
        6.5,
        "Enable HSTS after HTTPS is fully enforced (e.g., max-age=31536000; includeSubDomains).",
    ),
    "content-security-policy": (
        "Missing Content Security Policy (CSP)",
        6.5,
        "Define a CSP to reduce XSS risk (start with: default-src 'self').",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options (nosniff)",
        4.0,
        "Add X-Content-Type-Options: nosniff.",
    ),
    "x-frame-options": (
        "Missing clickjacking protection (X-Frame-Options)",
        4.0,
        "Add X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors).",
    ),
    "referrer-policy": (
        "Missing Referrer-Policy",
        3.5,
        "Add Referrer-Policy: strict-origin-when-cross-origin (or another policy suitable for your site).",
    ),
}

def check_headers(headers: dict) -> list[Finding]:
    findings: list[Finding] = []
    lower = {k.lower(): v for k, v in headers.items()}

    for key, (title, sev, rec) in RECOMMENDED.items():
        if key not in lower:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    title=f"{title} ({key})",
                    category="Headers",
                    severity=sev,
                    confidence=0.95,
                    description=f"The response is missing the '{key}' header, which helps harden browser security behavior.",
                    recommendation=rec,
                    evidence={"observed_headers": list(lower.keys())[:60]},
                )
            )

    for leak in ("server", "x-powered-by"):
        if leak in lower:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    title=f"Information disclosure header present: {leak}",
                    category="InfoLeak",
                    severity=2.5,
                    confidence=0.9,
                    description=f"The response includes '{leak}', which may reveal server or framework details helpful to attackers.",
                    recommendation="Remove or minimize technology/version details in response headers.",
                    evidence={leak: lower[leak]},
                )
            )

    return findings

