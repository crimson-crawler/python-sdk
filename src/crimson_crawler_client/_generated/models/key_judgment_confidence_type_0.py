from enum import Enum


class KeyJudgmentConfidenceType0(str, Enum):
    HIGH = "high"
    LOW = "low"
    MODERATE = "moderate"

    def __str__(self) -> str:
        return str(self.value)
