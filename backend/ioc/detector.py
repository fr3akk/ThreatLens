import ipaddress

from backend.schemas.ioc import IOCType
from backend.ioc.patterns import (
    DOMAIN_PATTERN,
    URL_PATTERN,
    MD5_PATTERN,
    SHA1_PATTERN,
    SHA256_PATTERN,
)


def detect_ioc_type(ioc: str) -> IOCType | None:
    """
    Detect the IOC type.

    Args:
        ioc: Indicator of Compromise provided by the user.

    Returns:
        IOCType if detected, otherwise None.
    """

    ioc = ioc.strip()

    # IPv4
    try:
        ipaddress.ip_address(ioc)
        return IOCType.IP
    except ValueError:
        pass

    # URL
    if URL_PATTERN.fullmatch(ioc):
        return IOCType.URL

    # Domain
    if DOMAIN_PATTERN.fullmatch(ioc):
        return IOCType.DOMAIN

    # MD5
    if MD5_PATTERN.fullmatch(ioc):
        return IOCType.MD5

    # SHA1
    if SHA1_PATTERN.fullmatch(ioc):
        return IOCType.SHA1

    # SHA256
    if SHA256_PATTERN.fullmatch(ioc):
        return IOCType.SHA256

    return None