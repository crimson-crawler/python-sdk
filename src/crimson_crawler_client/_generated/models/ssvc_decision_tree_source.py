from enum import Enum


class SSVCDecisionTreeSource(str, Enum):
    CSV = "csv"
    FALLBACK = "fallback"
    VERBATIM = "verbatim"

    def __str__(self) -> str:
        return str(self.value)
