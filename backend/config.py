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

    # Run the baseline detector (backend/services/ml/baseline.py) as each window of this many minutes
    # closes, writing its flags as Detection Findings. 0 leaves it off; POST /api/ml/baseline/run and
    # scripts/run_baseline.py run it on demand either way.
    BASELINE_EVERY_MINUTES: int = 0

    # Which part of TRACELOG this process is (docs/SERVICES.md). "all": everything in one process, as
    # `python run_app.py` runs it. "collector": the receivers, the one writer that archives and chains
    # every line, the outputs, and every request that changes data. "query": the read-only API behind
    # searches, verification, reports and analytics, which cannot change the archive.
    SERVICE_ROLE: str = "all"

    # Open the database read-only (the query and detector services): SQLite refuses every write.
    DB_READ_ONLY: bool = False

    # Where the detector service sends its findings, and the token if the collector's HTTP inputs
    # require one. The collector writes them into the chain, so there is still one writer.
    COLLECTOR_URL: str = "http://127.0.0.1:8000"
    COLLECTOR_TOKEN: str = ""

    # When the API does not answer, the dashboard runs the backend in its own process instead. Right
    # for one laptop; off in the containers, where the dashboard has no database and a second writer
    # would fork the hash chain.
    DASHBOARD_DIRECT_MODE: bool = True

    # Server settings
    BACKEND_HOST: str = "127.0.0.1"
    BACKEND_PORT: int = 8000
    FRONTEND_PORT: int = 8501

SUPPORTED_OCSF_VERSIONS = ("1.1.0", "1.2.0", "1.3.0")

SERVICE_ROLES = ("all", "collector", "query")

settings = Settings()
if settings.SERVICE_ROLE not in SERVICE_ROLES:
    raise ValueError(f"SERVICE_ROLE={settings.SERVICE_ROLE!r}; use one of {', '.join(SERVICE_ROLES)}")
if settings.OCSF_VERSION not in SUPPORTED_OCSF_VERSIONS:
    raise ValueError(
        f"OCSF_VERSION={settings.OCSF_VERSION!r} is not one TRACELOG emits. "
        f"Supported: {', '.join(SUPPORTED_OCSF_VERSIONS)}. Amazon Security Lake reads 1.3 and earlier; "
        f"see docs/adr/0001-ocsf-version.md before changing this.")
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
