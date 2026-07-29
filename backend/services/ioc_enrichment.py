from backend.analysis.risk_engine import RiskEngine
from backend.api.schemas.enrichment import EnrichmentResponse
from backend.connectors.virustotal import VirusTotalConnector
from backend.ioc.detector import detect_ioc_type
from backend.schemas.ioc import IOCType


class IOCEnrichmentService:
    def __init__(self):
        self.vt_connector = VirusTotalConnector()
        self.risk_engine = RiskEngine()

    def enrich(self, ioc: str) -> EnrichmentResponse:
        ioc_type = detect_ioc_type(ioc)

        if ioc_type is None:
            raise ValueError("Unsupported IOC type.")

        if ioc_type == IOCType.IP:
            threat = self.vt_connector.lookup(ioc, ioc_type)
            risk = self.risk_engine.calculate(threat)

            return EnrichmentResponse(
                threat=threat,
                risk=risk,
            )

        raise NotImplementedError(
            f"{ioc_type.value} enrichment is not implemented yet."
        )