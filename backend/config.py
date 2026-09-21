import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", env_file=".env")

    PROJECT_NAME: str = "Universal Log Pre-processing Framework (ULPF)"
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
    
    # Server settings
    BACKEND_HOST: str = "127.0.0.1"
    BACKEND_PORT: int = 8000
    FRONTEND_PORT: int = 8501

settings = Settings()
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
