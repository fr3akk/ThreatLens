from backend.ioc.detector import detect_ioc_type
from backend.schemas.ioc import IOCType


def test_detect_ipv4():
    assert detect_ioc_type("8.8.8.8") == IOCType.IP


def test_detect_domain():
    assert detect_ioc_type("example.com") == IOCType.DOMAIN


def test_detect_url():
    assert detect_ioc_type("https://example.com/login") == IOCType.URL


def test_detect_md5():
    assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == IOCType.MD5


def test_detect_sha1():
    assert (
        detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        == IOCType.SHA1
    )


def test_detect_sha256():
    assert (
        detect_ioc_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        == IOCType.SHA256
    )


def test_detect_invalid_ioc():
    assert detect_ioc_type("not-an-ioc") is None


def test_detect_strips_whitespace():
    assert detect_ioc_type("  8.8.8.8  ") == IOCType.IP