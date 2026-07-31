from enum import Enum


class InventoryEnrichmentJobResponseStatus(str, Enum):
    DONE = "done"
    ERROR = "error"
    QUEUED = "queued"
    RUNNING = "running"

    def __str__(self) -> str:
        return str(self.value)
