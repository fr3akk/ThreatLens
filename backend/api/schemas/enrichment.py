from pydantic import BaseModel

from backend.api.schemas.threat_response import ThreatResponse
from backend.api.schemas.risk import RiskAssessment


class EnrichmentResponse(BaseModel):
    threat: ThreatResponse
    risk: RiskAssessment