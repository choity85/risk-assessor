import uuid
from http.cookies import SimpleCookie
from ..types import Finding

def check_cookies(set_cookie_headers: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for raw in set_cookie_headers:
        c = SimpleCookie()
        c.load(raw)
        for name, _morsel in c.items():
            flags = raw.lower()
            missing = []
            if "secure" not in flags:
                missing.append("Secure")
            if "httponly" not in flags:
                missing.append("HttpOnly")
            if "samesite" not in flags:
                missing.append("SameSite")

            if missing:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=f"Cookie missing recommended flags: {name}",
                        category="Cookies",
                        severity=5.0,
                        confidence=0.85,
                        description=f"Cookie '{name}' is missing: {', '.join(missing)}.",
                        recommendation="Add Secure + HttpOnly where appropriate, and set SameSite to Lax/Strict based on intended behavior.",
                        evidence={"set_cookie": raw[:300]},
                    )
                )
    return findings
