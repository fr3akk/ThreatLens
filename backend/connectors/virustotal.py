from .base import BaseThreatConnector

class VirusTotalConnector(BaseThreatConnector):
    name = "VirusTotal"
    def lookup(self, ioc: str, ioc_type: str):
        raise NotImplementedError("This method should be implemented by subclasses.")