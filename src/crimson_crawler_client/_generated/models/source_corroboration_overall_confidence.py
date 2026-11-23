from enum import StrEnum


class SourceCorroborationOverallConfidence(StrEnum):
    HIGH = "high"
    LOW = "low"
    MODERATE = "moderate"

    def __str__(self) -> str:
        return str(self.value)
