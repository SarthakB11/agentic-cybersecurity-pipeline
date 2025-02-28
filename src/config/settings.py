from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    # Base paths
    BASE_DIR: Path = Path(__file__).parent.parent.parent
    LOGS_DIR: Path = BASE_DIR / "logs"
    DATA_DIR: Path = BASE_DIR / "data"
    
    # Tool configurations
    NMAP_PATH: str = "nmap"  # Assumes nmap is in PATH
    GOBUSTER_PATH: str = "gobuster"
    FFUF_PATH: str = "ffuf"
    SQLMAP_PATH: str = "sqlmap"
    
    # Tool timeout settings (in seconds)
    DEFAULT_TIMEOUT: int = 300
    NMAP_TIMEOUT: int = 600
    GOBUSTER_TIMEOUT: int = 300
    FFUF_TIMEOUT: int = 300
    SQLMAP_TIMEOUT: int = 600
    
    # Retry settings
    MAX_RETRIES: int = 3
    RETRY_DELAY: int = 5
    
    # Scope settings
    ALLOWED_DOMAINS: List[str] = Field(default_factory=list)
    ALLOWED_IPS: List[str] = Field(default_factory=list)
    EXCLUDED_PATHS: List[str] = Field(default_factory=list)
    
    # LangChain settings
    OPENAI_API_KEY: Optional[str] = None
    MODEL_NAME: str = "gpt-4"
    TEMPERATURE: float = 0.7
    
    # Logging settings
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Create singleton instance
settings = Settings()

# Ensure required directories exist
settings.LOGS_DIR.mkdir(parents=True, exist_ok=True)
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
