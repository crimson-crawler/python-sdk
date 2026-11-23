from enum import StrEnum


class ArtifactEnrichmentMetaOverallConfidenceType0(StrEnum):
    HIGH = "high"
    LOW = "low"
    MODERATE = "moderate"

    def __str__(self) -> str:
        return str(self.value)
