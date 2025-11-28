"""
logger_setup.py – Creates a reusable logger for consistent output formatting.
"""

import logging  # Built-in logging system
import sys      # For printing to standard output


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Creates and returns a logger with:
    - Timestamped output
    - UTC formatting
    - Consistent visual format
    """
    logger = logging.getLogger(name)

    # Avoid adding multiple handlers if logger already exists
    if logger.handlers:
        return logger

    # Format for logs: timestamp, level, logger name, message
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%SZ"

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt, datefmt))

    logger.addHandler(handler)
    logger.setLevel(level)

    return logger