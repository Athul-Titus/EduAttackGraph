"""
LLM-EduAttackGraph Backend Configuration

All configuration is loaded from environment variables (see .env.example).
Never hard-code secrets.
"""

from __future__ import annotations

import os
from enum import Enum
from typing import Optional, List

from pydantic import Field, field_validator, AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnvironment(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    DEMO = "demo"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class AuthorizedTargetMode(str, Enum):
    ALLOWLIST = "allowlist"
    LAB = "lab"  # Allow private IP ranges (192.168.x.x, 10.x.x.x, etc.)


class LLMProvider(str, Enum):
    DEEPSEEK = "deepseek"
    GROQ = "groq"
    NVIDIA = "nvidia"
    OPENAI = "openai"
    MOCK = "mock"


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    See .env.example for documentation on each variable.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    APP_ENV: AppEnvironment = AppEnvironment.DEVELOPMENT
    LOG_LEVEL: LogLevel = LogLevel.INFO
    SECRET_KEY: str = Field(
        default="change-this-in-production",
        description="Secret key for JWT and session management",
    )

    # --- Database ---
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./llm_edu_attackgraph.db",
        description="Database connection URL",
    )

    # --- FAISS ---
    FAISS_INDEX_PATH: str = "./data/indexes/faiss_index.bin"
    FAISS_METADATA_PATH: str = "./data/indexes/faiss_metadata.json"

    # --- Knowledge Base ---
    KNOWLEDGE_BASE_PATH: str = "./rag/data/processed"
    KNOWLEDGE_BASE_SOURCE: str = "awesome-poc"
    AWESOME_POC_REPO: str = "https://github.com/Threekiii/Awesome-POC.git"
    AWESOME_POC_LOCAL_PATH: str = "./rag/data/raw/awesome-poc"

    # --- Embedding ---
    # Paper: bge-small-zh; Implementation default: bge-m3 (multilingual)
    EMBEDDING_MODEL: str = "BAAI/bge-m3"
    EMBEDDING_DEVICE: str = "cpu"
    EMBEDDING_BATCH_SIZE: int = 32

    # --- RAG ---
    # Paper specifies: similarity_threshold = 0.6
    SIMILARITY_THRESHOLD: float = Field(default=0.60, ge=0.0, le=1.0)
    TOP_K: int = Field(default=5, ge=1, le=20)
    CHUNK_SIZE: int = Field(default=512, ge=64, le=2048)
    CHUNK_OVERLAP: int = Field(default=50, ge=0, le=200)

    # --- LLM ---
    LLM_PROVIDER: LLMProvider = LLMProvider.MOCK

    # DeepSeek
    DEEPSEEK_API_KEY: Optional[str] = None
    DEEPSEEK_BASE_URL: str = "https://api.deepseek.com"
    DEEPSEEK_MODEL: str = "deepseek-chat"
    DEEPSEEK_MAX_TOKENS: int = 2048
    DEEPSEEK_TEMPERATURE: float = 0.1

    # Groq
    GROQ_API_KEY: Optional[str] = None
    GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
    GROQ_MODEL: str = "llama-3.3-70b-versatile"

    # NVIDIA NIM
    NVIDIA_API_KEY: Optional[str] = None
    NVIDIA_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    NVIDIA_MODEL: str = "meta/llama-3.1-70b-instruct"

    # OpenAI
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4o-mini"

    # --- Authorization & Safety ---
    AUTHORIZED_TARGET_MODE: AuthorizedTargetMode = AuthorizedTargetMode.ALLOWLIST
    TARGET_ALLOWLIST: str = "localhost,127.0.0.1,::1"
    MAX_CONCURRENT_SCANS: int = 3
    SCAN_TIMEOUT: int = 300  # seconds

    # --- Fingerprinting ---
    PORT_GO_EXE_PATH: Optional[str] = None
    SERVER_GO_EXE_PATH: Optional[str] = None
    FINGER_EXE_PATH: Optional[str] = None
    SPARK_API_KEY: Optional[str] = None
    SPARK_API_URL: Optional[str] = None
    PORT_SCAN_TIMEOUT: int = 3
    PORT_SCAN_THREADS: int = 50
    PORT_SCAN_RANGE: str = "80,443,8080,8443,8888,3000,3306,5432,6379,9200,27017"
    SERVICE_BANNER_TIMEOUT: int = 5

    # --- Reports ---
    REPORTS_PATH: str = "./data/reports"

    # --- Demo Mode ---
    DEMO_FINGERPRINT_PATH: str = "./rag/data/samples/demo_fingerprint.json"
    DEMO_KB_PATH: str = "./rag/data/samples/demo_knowledge_base.json"

    # --- Prompts ---
    PROMPT_TEMPLATES_PATH: str = "./llm/prompts"
    PROMPT_VERSION: str = "v1"

    # --- API ---
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 1
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    @field_validator("SIMILARITY_THRESHOLD")
    @classmethod
    def validate_threshold(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("SIMILARITY_THRESHOLD must be between 0.0 and 1.0")
        return v

    @property
    def is_demo_mode(self) -> bool:
        return self.APP_ENV == AppEnvironment.DEMO

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == AppEnvironment.PRODUCTION

    @property
    def allowed_targets(self) -> List[str]:
        return [t.strip() for t in self.TARGET_ALLOWLIST.split(",") if t.strip()]

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def port_scan_ports(self) -> List[int]:
        """Parse PORT_SCAN_RANGE into a list of integers."""
        ports = []
        for part in self.PORT_SCAN_RANGE.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    pass
        return sorted(set(ports))

    @property
    def active_llm_api_key(self) -> Optional[str]:
        """Return the API key for the currently configured LLM provider."""
        mapping = {
            LLMProvider.DEEPSEEK: self.DEEPSEEK_API_KEY,
            LLMProvider.GROQ: self.GROQ_API_KEY,
            LLMProvider.NVIDIA: self.NVIDIA_API_KEY,
            LLMProvider.OPENAI: self.OPENAI_API_KEY,
            LLMProvider.MOCK: None,
        }
        return mapping.get(self.LLM_PROVIDER)


# Global settings instance — imported by other modules
settings = Settings()
