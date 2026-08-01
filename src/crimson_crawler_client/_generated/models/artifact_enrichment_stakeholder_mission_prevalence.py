from enum import Enum


class ArtifactEnrichmentStakeholderMissionPrevalence(str, Enum):
    ESSENTIAL = "essential"
    MINIMAL = "minimal"
    SUPPORT = "support"

    def __str__(self) -> str:
        return str(self.value)
