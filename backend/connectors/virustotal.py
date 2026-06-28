from .base import BaseThreatConnector
from backend.core.config import settings
from backend.api.schemas.threat_response import ThreatResponse, ThreatSummary

import requests


class VirusTotalConnector(BaseThreatConnector):
    name = "VirusTotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def lookup(self, ioc: str, ioc_type: str):
        if ioc_type != "ipv4":
            raise NotImplementedError("Currently only IPv4 lookups are supported.")

        headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY
        }

        url = f"{self.BASE_URL}/ip_addresses/{ioc}"

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(
                f"VirusTotal API request failed with status code {response.status_code}: {response.text}"
            )
        
        response_data = response.json()

        attributes = response_data["data"]["attributes"]
        stats = attributes["last_analysis_stats"]

        summary = ThreatSummary(
            malicious=stats["malicious"],
            suspicious=stats["suspicious"],
            harmless=stats["harmless"],
            undetected=stats["undetected"]
        )
        
        threat_response = ThreatResponse(
            provider=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            summary=summary,
            reputation=attributes["reputation"],
            analysis_date=attributes["last_analysis_date"],
            source_url=response_data["data"]["links"]["self"],
            raw=response_data
        )

        return threat_response
