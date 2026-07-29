from backend.ioc.detector import detect_ioc_type
from backend.connectors.virustotal import VirusTotalConnector
from backend.schemas.ioc import IOCType

class IOCEnrichmentService:
    def enrich(self, ioc: str):
        ioc_type = detect_ioc_type(ioc)

        if ioc_type is None:
            raise ValueError("Unsupported IOC type.")

        if ioc_type == IOCType.IP:
            connector = VirusTotalConnector()
            return connector.lookup(ioc, ioc_type)

        raise NotImplementedError(f"{ioc_type.value} enrichment is not implemented yet.")