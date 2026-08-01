from enum import Enum


class EnrichmentJobStageStatus(str, Enum):
    DONE = "done"
    ERROR = "error"
    PENDING = "pending"
    RUNNING = "running"
    SKIPPED = "skipped"

    def __str__(self) -> str:
        return str(self.value)
