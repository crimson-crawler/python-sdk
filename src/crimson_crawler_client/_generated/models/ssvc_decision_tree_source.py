from enum import StrEnum


class SSVCDecisionTreeSource(StrEnum):
    CSV = "csv"
    FALLBACK = "fallback"
    VERBATIM = "verbatim"

    def __str__(self) -> str:
        return str(self.value)
