from enum import StrEnum


class EnrichmentJobEventLevel(StrEnum):
    ERROR = "error"
    INFO = "info"
    WARN = "warn"

    def __str__(self) -> str:
        return str(self.value)
