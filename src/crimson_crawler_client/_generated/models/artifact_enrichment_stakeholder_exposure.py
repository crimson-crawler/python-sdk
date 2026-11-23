from enum import StrEnum


class ArtifactEnrichmentStakeholderExposure(StrEnum):
    CONTROLLED = "controlled"
    OPEN = "open"
    SMALL = "small"

    def __str__(self) -> str:
        return str(self.value)
