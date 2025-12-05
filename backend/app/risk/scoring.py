from .types import Finding

CATEGORY_WEIGHT = {
    "TLS": 1.4,
    "Headers": 1.1,
    "Cookies": 1.0,
    "InfoLeak": 0.6,
}

def score_findings(findings: list[Finding]) -> tuple[int, str]:
    total = 0.0
    for f in findings:
        w = CATEGORY_WEIGHT.get(f.category, 1.0)
        total += f.severity * f.confidence * w

    score = int(min(100, round(total * 2.2)))

    if score <= 20:
        level = "Low"
    elif score <= 40:
        level = "Medium"
    elif score <= 70:
        level = "High"
    else:
        level = "Critical"

    return score, level
