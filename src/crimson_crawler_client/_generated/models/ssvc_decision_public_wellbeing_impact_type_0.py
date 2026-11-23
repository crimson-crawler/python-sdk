from enum import StrEnum


class SSVCDecisionPublicWellbeingImpactType0(StrEnum):
    IRREVERSIBLE = "irreversible"
    MATERIAL = "material"
    MINIMAL = "minimal"

    def __str__(self) -> str:
        return str(self.value)
