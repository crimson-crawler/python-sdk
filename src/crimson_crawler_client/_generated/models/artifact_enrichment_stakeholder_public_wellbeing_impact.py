from enum import StrEnum


class ArtifactEnrichmentStakeholderPublicWellbeingImpact(StrEnum):
    IRREVERSIBLE = "irreversible"
    MATERIAL = "material"
    MINIMAL = "minimal"

    def __str__(self) -> str:
        return str(self.value)
