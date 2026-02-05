import os
import sys
from typing import Optional
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# 1. Force load the .env file
load_dotenv()

class Settings(BaseSettings):
    PROJECT_NAME: str = "Agentic Honey-Pot"
    GOOGLE_API_KEY: Optional[str] = os.getenv("GOOGLE_API_KEY")
    API_KEY: str = os.getenv("API_KEY", "helware-secret-key-2024")
    
    # STARTUP-GRADE SCALABILITY CONFIG
    # In production, swap SQLite for PostgreSQL
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///honey.db")
    # For distributed tracing
    SENTRY_DSN: Optional[str] = os.getenv("SENTRY_DSN")
    # Log level for structured logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Hugging Face compatibility: Use /tmp if SPACE_ID is set (HF Spaces)
    IS_HF: bool = os.getenv("SPACE_ID") is not None
    BASE_DATA_DIR: str = "/tmp/helware_data" if os.getenv("SPACE_ID") else os.getcwd()
    
    @property
    def DATABASE_PATH(self) -> str:
        path = os.path.join(self.BASE_DATA_DIR, "data", "honey.db")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    @property
    def CHECKPOINT_DB_PATH(self) -> str:
        path = os.path.join(self.BASE_DATA_DIR, "db", "checkpoints.sqlite")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    @property
    def VECTOR_DB_DIR(self) -> str:
        path = os.path.join(self.BASE_DATA_DIR, "db", "vector_store")
        os.makedirs(path, exist_ok=True)
        return path

    @property
    def REPORTS_DIR(self) -> str:
        path = os.path.join(self.BASE_DATA_DIR, "reports")
        os.makedirs(path, exist_ok=True)
        return path

    def validate_keys(self):
        if not self.GOOGLE_API_KEY:
            print("WARNING: GOOGLE_API_KEY not found. LLM features will fail.")
            # We don't exit(1) here to allow the app to start for non-LLM endpoints

settings = Settings()
settings.validate_keys()