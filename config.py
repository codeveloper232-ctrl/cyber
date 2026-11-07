"""
CYBERGUARD X System Configuration & Environment Parameters
"""

from pydantic_settings import BaseSettings
from typing import Optional, List

class Settings(BaseSettings):
    PROJECT_NAME: str = "CYBERGUARD X"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "production"
    
    # Auth & Security
    SECRET_KEY: str = "cyberguard-x-production-jwt-token-key-2026-secure"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./cyberguard.db"
    
    # External Threat Intelligence APIs
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    ALIENVAULT_OTX_KEY: Optional[str] = None
    
    # Multi-Signal Risk Engine Weights (Sum = 1.0)
    WEIGHT_REPUTATION: float = 0.25
    WEIGHT_STRUCTURAL: float = 0.20
    WEIGHT_NLP: float = 0.20
    WEIGHT_IMPERSONATION: float = 0.20
    WEIGHT_FINANCIAL: float = 0.15
    
    # Severity Score Thresholds
    CRITICAL_RISK_THRESHOLD: float = 85.0
    HIGH_RISK_THRESHOLD: float = 60.0
    MEDIUM_RISK_THRESHOLD: float = 35.0

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
