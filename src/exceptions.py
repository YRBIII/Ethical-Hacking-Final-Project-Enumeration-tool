"""
exceptions.py – Custom exceptions used across SonarTrace's backend.
"""


class EngineError(Exception):
    """
    Base class for backend-related errors.
    Helps catch all internal backend issues cleanly.
    """
    pass


class CommandFail(EngineError):
    """
    Raised when an external system command (like Nmap)
    fails or cannot be executed.
    """
    pass
