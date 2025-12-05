from fastapi import FastAPI
from datetime import datetime, timezone
import httpx

from .risk.types import ScanResult
from .risk.scoring import score_findings
from .risk.checks.tls import check_tls
from .risk.checks.headers import check_headers
from .risk.checks.cookies import check_cookies

app = FastAPI(title="Web Security Risk Assessor")

@app.post("/api/scan", response_model=ScanResult)
async def scan(payload: dict):
    url = (payload.get("url") or "").strip()
    if not url:
        # FastAPI will return 422 for missing fields normally,
        # but we keep this guard for safety.
        raise ValueError("url is required")

    findings = []
    findings += check_tls(url)

    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
        resp = await client.get(url, headers={"User-Agent": "RiskAssessor/1.0"})
        findings += check_headers(dict(resp.headers))

        set_cookie = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        findings += check_cookies(set_cookie)

    score, level = score_findings(findings)

    return ScanResult(
        target=url,
        scanned_at=datetime.now(timezone.utc),
        findings=findings,
        score=score,
        level=level
    )
