from pydantic import BaseModel

from backend.api.schemas.severity import Severity


class RiskAssessment(BaseModel):
    score: int
    severity: Severity