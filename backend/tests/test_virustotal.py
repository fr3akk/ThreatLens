from backend.connectors.virustotal import VirusTotalConnector
from backend.schemas.ioc import IOCType


def test_virustotal_ip_lookup(monkeypatch):
    connector = VirusTotalConnector()

    class FakeResponse:
        status_code = 200
        text = "OK"

        def json(self):
            return {
                "data": {
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
                    },
                    "attributes": {
                        "reputation": 561,
                        "last_analysis_date": 1790356180,
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 3,
                            "harmless": 50,
                            "undetected": 40,
                        },
                    },
                }
            }

    def fake_get(url, headers):
        return FakeResponse()

    monkeypatch.setattr(
        "backend.connectors.virustotal.requests.get",
        fake_get,
    )

    result = connector.lookup("8.8.8.8", IOCType.IP)

    assert result.provider == "VirusTotal"
    assert result.ioc == "8.8.8.8"
    assert result.ioc_type == IOCType.IP

    assert result.summary.malicious == 2
    assert result.summary.suspicious == 3
    assert result.summary.harmless == 50
    assert result.summary.undetected == 40

    assert result.reputation == 561
    assert result.analysis_date == 1790356180