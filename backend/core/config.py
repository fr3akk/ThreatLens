from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "ThreatLens API"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "SOC Automation & IOC Enrichment Platform"

    VIRUSTOTAL_API_KEY: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )


settings = Settings()