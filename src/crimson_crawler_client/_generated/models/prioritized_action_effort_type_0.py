from enum import Enum


class PrioritizedActionEffortType0(str, Enum):
    LOW = "low"
    MEDIUM = "medium"

    def __str__(self) -> str:
        return str(self.value)
