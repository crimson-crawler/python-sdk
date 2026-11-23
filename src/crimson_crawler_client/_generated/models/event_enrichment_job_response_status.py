from enum import StrEnum


class EventEnrichmentJobResponseStatus(StrEnum):
    DONE = "done"
    ERROR = "error"
    QUEUED = "queued"
    RUNNING = "running"

    def __str__(self) -> str:
        return str(self.value)
