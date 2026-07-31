from enum import Enum


class ArtifactEnrichmentStakeholderHumanImpact(str, Enum):
    HIGH = "high"
    LOW = "low"
    MEDIUM = "medium"
    VERY_HIGH = "very_high"

    def __str__(self) -> str:
        return str(self.value)
