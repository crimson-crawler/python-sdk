from enum import StrEnum


class BatchItemResultStatus(StrEnum):
    ERROR = "error"
    OK = "ok"

    def __str__(self) -> str:
        return str(self.value)
