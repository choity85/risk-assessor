from pydantic import BaseModel, Field
from typing import Dict, Any, List, Literal
from datetime import datetime

Category = Literal["TLS", "Headers", "Cookies", "InfoLeak"]

class Finding(BaseModel):
    id: str
    title: str
    category: Category
    severity: float = Field(ge=0, le=10)
    confidence: float = Field(ge=0, le=1)
    description: str
    recommendation: str
    evidence: Dict[str, Any] = Field(default_factory=dict)

class ScanResult(BaseModel):
    target: str
    scanned_at: datetime
    findings: List[Finding]
    score: int
    level: Literal["Low","Medium","High","Critical"]
