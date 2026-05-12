import os
import sys
import structlog
import logging

def configure_logger():
    """Configure structlog for JSON or console output."""
    json_output = os.environ.get("AEGIS_LOG_JSON", "0") == "1"
    log_level = os.environ.get("AEGIS_LOG_LEVEL", "INFO").upper()
    
    # Map level name to integer
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    numeric_level = level_map.get(log_level, logging.INFO)

    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

# Run configuration on import
configure_logger()
logger = structlog.get_logger("aegis")

def get_logger(name: str = "aegis"):
    return structlog.get_logger(name)
