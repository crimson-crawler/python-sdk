from enum import Enum


class ArtifactEnrichmentStakeholderPublicWellbeingImpact(str, Enum):
    IRREVERSIBLE = "irreversible"
    MATERIAL = "material"
    MINIMAL = "minimal"

    def __str__(self) -> str:
        return str(self.value)
