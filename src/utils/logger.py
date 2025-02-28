import sys
from pathlib import Path
from loguru import logger
from ..config.settings import settings

def setup_logger():
    """Configure the logger with custom settings."""
    # Remove default handler
    logger.remove()
    
    # Add console handler
    logger.add(
        sys.stdout,
        format=settings.LOG_FORMAT,
        level=settings.LOG_LEVEL,
        colorize=True
    )
    
    # Add file handler for all logs
    log_file = settings.LOGS_DIR / "cybersec_pipeline.log"
    logger.add(
        str(log_file),
        rotation="500 MB",
        retention="10 days",
        format=settings.LOG_FORMAT,
        level=settings.LOG_LEVEL,
        compression="zip"
    )
    
    # Add file handler for errors only
    error_log = settings.LOGS_DIR / "errors.log"
    logger.add(
        str(error_log),
        rotation="100 MB",
        retention="30 days",
        format=settings.LOG_FORMAT,
        level="ERROR",
        compression="zip"
    )
    
    return logger

# Create singleton instance
logger = setup_logger()
