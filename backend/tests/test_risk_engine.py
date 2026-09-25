from backend.analysis.risk_engine import RiskEngine
from backend.api.schemas.severity import Severity
from backend.api.schemas.threat_response import ThreatResponse, ThreatSummary


def make_threat(malicious, suspicious, harmless, undetected):
    return ThreatResponse(
        provider="Test",
        ioc="8.8.8.8",
        ioc_type="ip",
        summary=ThreatSummary(
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
        ),
    )


def test_zero_total():
    threat = make_threat(0, 0, 0, 0)

    result = RiskEngine().calculate(threat)

    assert result.score == 0
    assert result.severity == Severity.LOW


def test_low_risk():
    threat = make_threat(1, 0, 99, 0)

    result = RiskEngine().calculate(threat)

    assert result.score == 1
    assert result.severity == Severity.LOW


def test_medium_risk():
    threat = make_threat(25, 0, 75, 0)

    result = RiskEngine().calculate(threat)

    assert result.score == 25
    assert result.severity == Severity.MEDIUM


def test_high_risk():
    threat = make_threat(50, 0, 50, 0)

    result = RiskEngine().calculate(threat)

    assert result.score == 50
    assert result.severity == Severity.HIGH


def test_critical_risk():
    threat = make_threat(75, 0, 25, 0)

    result = RiskEngine().calculate(threat)

    assert result.score == 75
    assert result.severity == Severity.CRITICAL


def test_fully_malicious():
    threat = make_threat(100, 0, 0, 0)

    result = RiskEngine().calculate(threat)

    assert result.score == 100
    assert result.severity == Severity.CRITICAL