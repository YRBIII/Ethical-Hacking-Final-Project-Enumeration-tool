class EnumerationError(Exception):
    """Base exception for enumeration errors."""


class CommandExecutionError(EnumerationError):
    """Raised when an external command fails."""
    def __init__(self, command: str, return_code: int, output: str):
        self.command = command
        self.return_code = return_code
        self.output = output
        super().__init__(f"Command '{command}' failed with return code {return_code}. Output: {output}")