from enum import Enum


class EnrichmentJobEventLevel(str, Enum):
    ERROR = "error"
    INFO = "info"
    WARN = "warn"

    def __str__(self) -> str:
        return str(self.value)
