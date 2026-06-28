from pydantic import BaseModel
from typing import Any, Optional

class ThreatSummary(BaseModel):
    malicious: int
    suspicious: int
    harmless: int
    undetected: int

class ThreatResponse(BaseModel):
    provider: str
    ioc: str
    ioc_type: str
    summary: ThreatSummary
    reputation: Optional[int] = None
    analysis_date: Optional[int] = None
    source_url: Optional[str] = None
    raw: Optional[Any] = None

