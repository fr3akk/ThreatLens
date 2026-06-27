from pydantic import BaseModel


class Settings(BaseModel):
    APP_NAME: str = "ThreatLens API"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "SOC Automation & IOC Enrichment Platform"


settings = Settings()