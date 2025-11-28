"""
config.py – Stores global constants used across SonarTrace.
"""

from pathlib import Path  # Handles file paths in a cross-platform way

# Prefix used to generate default report file names
DEFAULT_REPORT_PREFIX = "sonartrace_report"

# Default directory where reports are saved
DEFAULT_OUTPUT_DIR = Path.cwd()
