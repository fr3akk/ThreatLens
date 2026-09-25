from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app, raise_server_exceptions=False)


def test_enrich_ip():
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
                            "malicious": 10,
                            "suspicious": 5,
                            "harmless": 50,
                            "undetected": 35,
                        },
                    },
                }
            }

    def fake_get(url, headers):
        return FakeResponse()

    import backend.connectors.virustotal

    original_get = backend.connectors.virustotal.requests.get
    backend.connectors.virustotal.requests.get = fake_get

    try:
        response = client.post(
            "/ioc/enrich",
            json={"ioc": "8.8.8.8"},
        )
    finally:
        backend.connectors.virustotal.requests.get = original_get

    assert response.status_code == 200

    data = response.json()

    assert data["threat"]["provider"] == "VirusTotal"
    assert data["threat"]["ioc"] == "8.8.8.8"
    assert data["threat"]["ioc_type"] == "ip"

    assert data["threat"]["summary"]["malicious"] == 10
    assert data["threat"]["summary"]["suspicious"] == 5
    assert data["threat"]["summary"]["harmless"] == 50
    assert data["threat"]["summary"]["undetected"] == 35

    assert data["threat"]["reputation"] == 561

    assert data["risk"]["score"] == 10
    assert data["risk"]["severity"] == "low"

def test_enrich_unsupported_ioc_type():
    response = client.post(
        "/ioc/enrich",
        json={"ioc": "example.com"},
    )

    assert response.status_code == 501

    data = response.json()

    assert data["detail"] == "domain enrichment is not implemented yet."