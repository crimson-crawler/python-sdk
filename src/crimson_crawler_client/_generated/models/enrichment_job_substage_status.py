from enum import StrEnum


class EnrichmentJobSubstageStatus(StrEnum):
    DONE = "done"
    ERROR = "error"
    PENDING = "pending"
    RUNNING = "running"
    SKIPPED = "skipped"

    def __str__(self) -> str:
        return str(self.value)
