from enum import Enum


class ArtifactEnrichmentStakeholderExposure(str, Enum):
    CONTROLLED = "controlled"
    OPEN = "open"
    SMALL = "small"

    def __str__(self) -> str:
        return str(self.value)
