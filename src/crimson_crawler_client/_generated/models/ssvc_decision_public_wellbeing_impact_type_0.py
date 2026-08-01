from enum import Enum


class SSVCDecisionPublicWellbeingImpactType0(str, Enum):
    IRREVERSIBLE = "irreversible"
    MATERIAL = "material"
    MINIMAL = "minimal"

    def __str__(self) -> str:
        return str(self.value)
