from enum import StrEnum


class PrioritizedActionEffortType0(StrEnum):
    LOW = "low"
    MEDIUM = "medium"

    def __str__(self) -> str:
        return str(self.value)
