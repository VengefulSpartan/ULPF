import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", env_file=".env")

    PROJECT_NAME: str = "TRACELOG — Universal Log Pre-processing Framework"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    
    # Storage settings
    DATA_DIR: Path = BASE_DIR / "data"
    DB_PATH: Path = BASE_DIR / "data" / "ulpf.db"
    
    # Environment
    ENVIRONMENT: str = "local" # local, demo, production
    DEBUG: bool = True
    
    # Optional LLM Key (for offline mode, left empty)
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    
    # The OCSF schema version events are stamped with and validated against. 1.1.0 by default;
    # docs/adr/0001-ocsf-version.md explains why, and the list is what TRACELOG has verified its
    # four classes against, not what OCSF has released (1.9.0 at the time of writing).
    OCSF_VERSION: str = "1.1.0"

    # Full-text index over the archived lines. On, searching 100k stored lines for an address takes
    # under a millisecond instead of a third of a second; off, ingestion is about a quarter faster
    # (scripts/benchmark.py measures both). Turn it off for a pure forwarder that is never searched.
    SEARCH_INDEX: bool = True

    # Server settings
    BACKEND_HOST: str = "127.0.0.1"
    BACKEND_PORT: int = 8000
    FRONTEND_PORT: int = 8501

SUPPORTED_OCSF_VERSIONS = ("1.1.0", "1.2.0", "1.3.0")

settings = Settings()
if settings.OCSF_VERSION not in SUPPORTED_OCSF_VERSIONS:
    raise ValueError(
        f"OCSF_VERSION={settings.OCSF_VERSION!r} is not one TRACELOG emits. "
        f"Supported: {', '.join(SUPPORTED_OCSF_VERSIONS)}. Amazon Security Lake reads 1.3 and earlier; "
        f"see docs/adr/0001-ocsf-version.md before changing this.")
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
