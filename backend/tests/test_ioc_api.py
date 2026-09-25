from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def test_detect_valid_ip():
    response = client.post(
        "/ioc/detect",
        json={"ioc": "8.8.8.8"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["valid"] is True
    assert data["type"] == "ip"
    assert data["value"] == "8.8.8.8"
    assert data["error"] is None


def test_detect_valid_domain():
    response = client.post(
        "/ioc/detect",
        json={"ioc": "example.com"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["valid"] is True
    assert data["type"] == "domain"
    assert data["value"] == "example.com"
    assert data["error"] is None


def test_detect_invalid_ioc():
    response = client.post(
        "/ioc/detect",
        json={"ioc": "not-an-ioc"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["valid"] is False
    assert data["type"] is None
    assert data["value"] is None
    assert data["error"] == "Unsupported IOC format"


def test_detect_strips_whitespace():
    response = client.post(
        "/ioc/detect",
        json={"ioc": "  8.8.8.8  "},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["valid"] is True
    assert data["type"] == "ip"
    assert data["value"] == "8.8.8.8"