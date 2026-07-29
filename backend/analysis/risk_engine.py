from backend.api.schemas.threat_response import ThreatResponse
from backend.api.schemas.risk import RiskAssessment
from backend.api.schemas.severity import Severity

class RiskEngine:
    def calculate(self, threat_response: ThreatResponse) -> RiskAssessment:
        stats = threat_response.summary
        total = (
            stats.malicious
            + stats.suspicious
            + stats.harmless
            + stats.undetected
        )

        if total == 0:
            score = 0
        else: 
            score = round((stats.malicious / total) * 100)

        if 0 <= score <= 24:
            severity = Severity.LOW
        elif 25 <= score <= 49:
            severity = Severity.MEDIUM
        elif 50 <= score <= 74:
            severity = Severity.HIGH
        else:
            severity = Severity.CRITICAL

        return RiskAssessment(
            score=score,
            severity=severity
        )

