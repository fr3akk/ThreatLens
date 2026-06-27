import re

DOMAIN_PATTERN = re.compile(
    r"^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)

URL_PATTERN = re.compile(
    r"^https?://[^\s/$.?#].[^\s]*$",
    re.IGNORECASE,
)

MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")

SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")

SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")