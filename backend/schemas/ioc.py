from enum import Enum

from pydantic import BaseModel


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class IOCRequest(BaseModel):
    ioc: str


class IOCResponse(BaseModel):
    valid: bool
    type: IOCType | None = None
    value: str | None = None
    error: str | None = None