from enum import StrEnum


class EnrichCVERequestTechniquesScope(StrEnum):
    ALL = "all"
    SPECIFIC = "specific"

    def __str__(self) -> str:
        return str(self.value)
